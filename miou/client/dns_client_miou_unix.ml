module IM = Map.Make (Int)

let src = Logs.Src.create "dns_client_miou_unix"
module Log = (val Logs.src_log src : Logs.LOG)

(* replacement for Lwt_condition *)
module Promise = struct
  type 'a t = {
    mutex: Miou.Mutex.t;
    cond : Miou.Condition.t;
    mutable value: 'a option;
  }

  let create () = {
    mutex = Miou.Mutex.create ();
    cond = Miou.Condition.create ();
    value = None
  }

  let broadcast t v = Miou.Mutex.protect t.mutex @@ fun () ->
    t.value <- Some v;
    Miou.Condition.broadcast t.cond

  let wait t = Miou.Mutex.protect t.mutex @@ fun () ->
    Miou.Condition.wait t.cond t.mutex;
    Option.get t.value
end

module Transport = struct
  type io_addr = [ `Plaintext of Ipaddr.t * int | `Tls of Tls.Config.client * Ipaddr.t * int ]
  type +'a io = 'a
  type stack = Happy_eyeballs_miou_unix.t
  type nameservers =
  | Static of io_addr list
  | Resolv_conf of {
    mutable nameservers: io_addr list;
    mutable digest: Digest.t option;
  }
  type t = {
    nameservers: nameservers;
    timeout_ns: int64;
    he: Happy_eyeballs_miou_unix.t;
    mutable fd: [ `Plain of Miou_unix.file_descr | `Tls of Tls_miou_unix.t ] option;
    mutable requests: (Cstruct.t * (Cstruct.t, [ `Msg of string ]) result Promise.t) IM.t;
    mutable connected_prom: (unit, [ `Msg of string ]) result Promise.t option
  }
  type context = t

  let read_file file =
    try
      let fh = open_in file in
      try
        let content = really_input_string fh (in_channel_length fh) in
        close_in_noerr fh ;
        Ok content
      with _ ->
        close_in_noerr fh;
        Error (`Msg ("Error reading file: " ^ file))
    with _ -> Error (`Msg ("Error opening file " ^ file))

  let authenticator =
    let authenticator_ref = ref None in
    fun () ->
      match !authenticator_ref with
      | Some x -> x
      | None -> match Ca_certs.authenticator () with
        | Ok a -> authenticator_ref := Some a ; a
        | Error `Msg m -> invalid_arg ("failed to load trust anchors: " ^ m)

  let decode_resolv_conf data =
    let ( let* ) = Result.bind in
    let authenticator = authenticator () in
    let* ns = Dns_resolvconf.parse data in
    match
      List.flatten
        (List.map
            (fun (`Nameserver ip) ->
              let tls = Tls.Config.client ~authenticator ~ip () in
              [ `Tls (tls, ip, 853) ; `Plaintext (ip, 53) ])
            ns)
    with
    | [] -> Error (`Msg "no nameservers in resolv.conf")
    | ns -> Ok ns

  let resolv_conf () =
    let ( let* ) = Result.bind in
    let* data = read_file "/etc/resolv.conf" in
    let* ns =
      Result.map_error
        (function `Msg msg ->
            Log.warn (fun m -> m "error %s decoding resolv.conf %S" msg data);
            `Msg msg)
        (decode_resolv_conf data)
    in
    Ok (ns, Digest.string data)

  let default_resolver () =
    let authenticator = authenticator () in
    let peer_name = Dns_client.default_resolver_hostname in
    let tls_config = Tls.Config.client ~authenticator ~peer_name () in
    List.map (fun ip -> `Tls (tls_config, ip, 853)) Dns_client.default_resolvers
  
  let maybe_resolv_conf t =
    match t.nameservers with
    | Static _ -> ()
    | Resolv_conf resolv_conf ->
      let needs_update =
        match read_file "/etc/resolv.conf", resolv_conf.digest with
        | Ok data, Some dgst ->
          let dgst' = Digest.string data in
          if Digest.equal dgst' dgst then
            `No
          else
            `Data (data, dgst')
        | Ok data, None ->
          let digest = Digest.string data in
          `Data (data, digest)
        | Error _, None ->
          `No
        | Error `Msg msg, Some _ ->
          Log.warn (fun m -> m "error reading /etc/resolv.conf: %s" msg);
          `Default
      in
      match needs_update with
      | `No -> ()
      | `Default ->
        resolv_conf.digest <- None;
        resolv_conf.nameservers <- default_resolver ()
      | `Data (data, dgst) ->
        match decode_resolv_conf data with
        | Ok ns ->
          resolv_conf.digest <- Some dgst;
          resolv_conf.nameservers <- ns
        | Error `Msg msg ->
          Log.warn (fun m -> m "error %s decoding resolv.conf: %S" msg data);
          resolv_conf.digest <- None;
          resolv_conf.nameservers <- default_resolver ()

  let create ?nameservers ~timeout happy_eyeballs =
    let nameservers =
      match nameservers with
      | Some (`Udp, _) -> invalid_arg "UDP is not supported"
      | Some (`Tcp, ns) -> Static ns
      | None ->
        match resolv_conf () with
        | Error _ -> Resolv_conf { nameservers = default_resolver (); digest = None }
        | Ok (ips, digest) -> Resolv_conf { nameservers = ips; digest = Some digest }
    in {
      nameservers;
      timeout_ns = timeout;
      fd = None;
      he = happy_eyeballs;
      requests = IM.empty;
      connected_prom = None;
    }

  let nameserver_ips = function
  | Static nameservers -> nameservers
  | Resolv_conf { nameservers; _ } -> nameservers

  let nameservers { nameservers; _ } = `Tcp, nameserver_ips nameservers

  let rng = Mirage_crypto_rng.generate ?g:None

  let clock = Mtime_clock.elapsed_ns

  let to_pairs =
    List.map (function `Plaintext (ip, port) | `Tls (_, ip, port) -> ip, port)

  let close_socket fd =
    try Miou_unix.close fd with _ -> ()

  let rec read_loop ?(linger = Cstruct.empty) (t: t) fd =
    let result =
      try
        match fd with
        | `Plain fd ->
          let recv_buffer = Bytes.make 2048 '\000' in
          let r = Miou_unix.read ~len:(Bytes.length recv_buffer) fd recv_buffer in
          r, Cstruct.of_bytes recv_buffer
        | `Tls fd ->
          let recv_buffer = Bytes.make 2048 '\000' in
          let r = Tls_miou_unix.read ~len:(Bytes.length recv_buffer) fd recv_buffer in
          r, Cstruct.of_bytes recv_buffer
      with e ->
        Logs.err (fun m -> m "error %s reading from resolver" (Printexc.to_string e));
        0, Cstruct.empty
    in
    match result with
    | 0, _ ->
      (
        match fd with
        | `Plain fd -> close_socket fd
        | `Tls fd -> Tls_miou_unix.close fd
      );
      t.fd <- None;
      if not (IM.is_empty t.requests) then
        Logs.info (fun m -> m "end of file reading from resolver")
    | read_len, cs ->
      let rec handle_data data =
        let cs_len = Cstruct.length data in
        if cs_len > 2 then
          let len = Cstruct.BE.get_uint16 data 0 in
          if cs_len - 2 >= len then
            let packet, rest =
              if cs_len - 2 = len then data, Cstruct.empty
              else Cstruct.split data (len + 2)
            in
            let id = Cstruct.BE.get_uint16 packet 2 in
            (
              match IM.find_opt id t.requests with
              | None -> Log.warn (fun m -> m "received unsolicited data, ignoring")
              | Some (_, prom) -> Promise.broadcast prom (Ok packet)
            );
            handle_data rest
          else
            read_loop ~linger:data t fd
        else
          read_loop ~linger:data t fd
      in
      let cs = Cstruct.sub cs 0 read_len in
      handle_data (if Cstruct.length linger = 0 then cs else Cstruct.append linger cs)

  let send_query fd tx =
    try
      match fd with
      | `Plain fd -> Miou_unix.write fd (Cstruct.to_string tx); Ok ()
      | `Tls fd -> Tls_miou_unix.write fd (Cstruct.to_string tx); Ok ()
    with e -> Error (`Msg (Printexc.to_string e))

  let req_all fd t =
    IM.fold (fun _id (data, _) r ->
      match r with
      | Error _ as e -> e
      | Ok () -> send_query fd data
    ) t.requests (Ok ())

  let find_ns ns (addr, port) =
    List.find (function `Plaintext (ip, p) | `Tls (_, ip, p) ->
      Ipaddr.compare ip addr = 0 && p = port
    ) ns

  let rec connect_to_ns_list (t: t) connected_prom nameservers =
    let ns = to_pairs nameservers in
    match Happy_eyeballs_miou_unix.connect_ip ~connect_timeout:t.timeout_ns t.he ns with
    | Error `Msg msg ->
      let err =
        Error (`Msg (Fmt.str "error %s connecting to resolver %a"
                      msg
                      Fmt.(list ~sep:(any ", ") (pair ~sep:(any ":") Ipaddr.pp int))
                      (to_pairs (nameserver_ips t.nameservers))))
      in
      err
    | Ok (addr, socket) ->
      let continue socket =
        t.fd <- Some socket;
        read_loop t socket;
        if not (IM.is_empty t.requests) then (
          match connect_via_tcp_to_ns t with
          | Error (`Msg msg) -> Log.err (fun m -> m "error while connecting to resolver: %s" msg)
          | Ok () -> ()
        );
        Promise.broadcast connected_prom (Ok ());
        t.connected_prom <- None;
        req_all socket t
      in
      let config = find_ns (nameserver_ips t.nameservers) addr in
      match config with
      | `Plaintext _ -> continue (`Plain socket)
      | `Tls (tls_cfg, _, _) ->
        try
          continue (`Tls (Tls_miou_unix.client_of_fd tls_cfg socket))
        with e -> Logs.warn (fun m -> m "TLS handshake with %a:%d failed: %s" Ipaddr.pp (fst addr) (snd addr) (Printexc.to_string e));
        let ns' =
          List.filter (function
          | `Tls (_, ip, port) -> not (Ipaddr.compare ip (fst addr) = 0 && port = snd addr)
          | _ -> true
          ) nameservers
        in
        if ns' = [] then (
          let err = Error (`Msg "no further nameservers configured") in
          Promise.broadcast connected_prom err;
          t.connected_prom <- None;
          err
        ) else connect_to_ns_list t connected_prom ns'
  and connect_via_tcp_to_ns (t: t) =
    match t.fd, t.connected_prom with
    | Some _, _ -> Ok ()
    | None, Some w -> Promise.wait w
    | None, None ->
      let connected_prom = Promise.create () in
      t.connected_prom <- Some connected_prom;
      maybe_resolv_conf t;
      connect_to_ns_list t connected_prom (nameserver_ips t.nameservers)

  let connect t =
    match connect_via_tcp_to_ns t with
    | Ok () -> Ok (`Tcp, t)
    | Error `Msg msg -> Error (`Msg msg)

  let with_timeout timeout f =
    let timeout () =
      Miou_unix.sleep (Duration.to_f timeout);
      Error (`Msg "DNS request timeout")
    in
    Result.get_ok @@ Miou.await_first [ Miou.async f; Miou.async timeout ]

  let send_recv (t: context) tx : (Cstruct.t, [ `Msg of string ]) result :> (Cstruct.t, [> `Msg of string ]) result =
    if Cstruct.length tx > 4 then
      match t.fd with
      | None -> Error (`Msg "no connection to the nameserver established")
      | Some fd ->
        let id = Cstruct.BE.get_uint16 tx 2 in
        with_timeout t.timeout_ns (fun () ->
          Result.bind (send_query fd tx) @@ fun () ->
          let prom = Promise.create () in
          t.requests <- IM.add id (tx, prom) t.requests;
          let r = Promise.wait prom in
          t.requests <- IM.remove id t.requests;
          r
        )
    else
      Error (`Msg "invalid DNS packet (data length <= 4)")

  let close _ = ()

  let bind r f = f r

  let lift f = f
end

include Dns_client.Make (Transport)