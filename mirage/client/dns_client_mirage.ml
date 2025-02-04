open Lwt.Infix

let src = Logs.Src.create "dns_client_mirage" ~doc:"effectful DNS client layer"
module Log = (val Logs.src_log src : Logs.LOG)

module IM = Map.Make(Int)

module Make (R : Mirage_random.S) (T : Mirage_time.S) (M : Mirage_clock.MCLOCK) (P : Mirage_clock.PCLOCK) (S : Mirage_stack.V4V6) = struct

  module TLS = Tls_mirage.Make(S.TCP)
  module CA = Ca_certs_nss.Make(P)

  module Transport : Dns_client.S
    with type stack = S.t
     and type +'a io = 'a Lwt.t
     and type io_addr = [ `Plaintext of Ipaddr.t * int | `Tls of Tls.Config.client * Ipaddr.t * int ] = struct
    type stack = S.t
    type io_addr = [ `Plaintext of Ipaddr.t * int | `Tls of Tls.Config.client * Ipaddr.t * int ]
    type +'a io = 'a Lwt.t
    type t = {
      nameservers : io_addr list ;
      timeout_ns : int64 ;
      stack : stack ;
      mutable flow : [`Plain of S.TCP.flow | `Tls of TLS.flow ] option ;
      mutable requests : (Cstruct.t * (Cstruct.t, [ `Msg of string ]) result Lwt_condition.t) IM.t ;
      mutable he : Happy_eyeballs.t ;
      mutable waiters : ((Ipaddr.t * int) * S.TCP.flow, [ `Msg of string ]) result Lwt.u Happy_eyeballs.Waiter_map.t ;
      timer_condition : unit Lwt_condition.t ;
    }
    type context = t

    let clock = M.elapsed_ns
    let he_timer_interval = Duration.of_ms 500

    let rec handle_action t action =
      (match action with
       | Happy_eyeballs.Connect (host, id, addr) ->
         begin
           S.TCP.create_connection (S.tcp t.stack) addr >>= function
           | Error e ->
             Log.err (fun m -> m "error connecting to nameserver %a: %a"
                         Ipaddr.pp (fst addr) S.TCP.pp_error e) ;
             Lwt.return (Some (Happy_eyeballs.Connection_failed (host, id, addr)))
           | Ok flow ->
             let waiters, r = Happy_eyeballs.Waiter_map.find_and_remove id t.waiters in
             t.waiters <- waiters;
             begin match r with
               | Some waiter -> Lwt.wakeup_later waiter (Ok (addr, flow)); Lwt.return_unit
               | None -> S.TCP.close flow
             end >|= fun () ->
             Some (Happy_eyeballs.Connected (host, id, addr))
         end
       | Connect_failed (_host, id) ->
         let waiters, r = Happy_eyeballs.Waiter_map.find_and_remove id t.waiters in
         t.waiters <- waiters;
         begin match r with
           | Some waiter -> Lwt.wakeup_later waiter (Error (`Msg "connection failed"))
           | None -> ()
         end;
         Lwt.return None
       | a ->
         Log.warn (fun m -> m "ignoring action %a" Happy_eyeballs.pp_action a);
         Lwt.return None) >>= function
       | None -> Lwt.return_unit
       | Some event ->
         let he, actions = Happy_eyeballs.event t.he (clock ()) event in
         t.he <- he;
         Lwt_list.iter_p (handle_action t) actions

    let handle_timer_actions t actions =
      Lwt.async (fun () -> Lwt_list.iter_p (fun a -> handle_action t a) actions)

    let rec he_timer t =
      let open Lwt.Infix in
      let rec loop () =
        let he, cont, actions = Happy_eyeballs.timer t.he (clock ()) in
        t.he <- he ;
        handle_timer_actions t actions ;
        match cont with
        | `Suspend -> he_timer t
        | `Act ->
          T.sleep_ns he_timer_interval >>= fun () ->
          loop ()
      in
      Lwt_condition.wait t.timer_condition >>= fun () ->
      loop ()

    let create ?nameservers ~timeout stack =
      let nameservers = match nameservers with
        | None | Some (`Tcp, []) ->
          let authenticator = match CA.authenticator () with
            | Ok a -> a
            | Error `Msg m -> invalid_arg ("bad CA certificates " ^ m)
          in
          let tls_cfg =
            let peer_name = Dns_client.default_resolver_hostname in
            Tls.Config.client ~authenticator ~peer_name ()
          in
          List.flatten
            (List.map
               (fun ip -> [ `Tls (tls_cfg, ip, 853) ; `Plaintext (ip, 53) ])
               Dns_client.default_resolvers)
        | Some (`Udp, _) -> invalid_arg "UDP is not supported"
        | Some (`Tcp, ns) -> ns
      in
      let t = {
        nameservers ;
        timeout_ns = timeout ;
        stack ;
        flow = None ;
        requests = IM.empty ;
        he = Happy_eyeballs.create (clock ()) ;
        waiters = Happy_eyeballs.Waiter_map.empty ;
        timer_condition = Lwt_condition.create () ;
      } in
      Lwt.async (fun () -> he_timer t);
      t

    let nameservers { nameservers ; _ } = `Tcp, nameservers
    let rng = R.generate ?g:None

    let with_timeout time_left f =
      let timeout =
        T.sleep_ns time_left >|= fun () ->
        Error (`Msg "DNS request timeout")
      in
      Lwt.pick [ f ; timeout ]

    let bind = Lwt.bind
    let lift = Lwt.return

    let rec read_loop ?(linger = Cstruct.empty) t flow =
      let process cs =
        let rec handle_data data =
          let cs_len = Cstruct.length data in
          if cs_len > 2 then
            let len = Cstruct.BE.get_uint16 data 0 in
            if cs_len - 2 >= len then
              let packet, rest =
                if cs_len - 2 = len
                then data, Cstruct.empty
                else Cstruct.split data (len + 2)
              in
              let id = Cstruct.BE.get_uint16 packet 2 in
              (match IM.find_opt id t.requests with
               | None -> Log.warn (fun m -> m "received unsolicited data, ignoring")
               | Some (_, cond) -> Lwt_condition.broadcast cond (Ok packet));
              handle_data rest
            else
              read_loop ~linger:data t flow
          else
            read_loop ~linger:data t flow
        in
        handle_data (if Cstruct.length linger = 0 then cs else Cstruct.append linger cs)
      in
      match flow with
      | `Plain flow ->
        begin
          S.TCP.read flow >>= function
          | Error e ->
            t.flow <- None;
            Log.err (fun m -> m "error %a reading from resolver" S.TCP.pp_error e);
            Lwt.return_unit
          | Ok `Eof ->
            t.flow <- None;
            Log.info (fun m -> m "end of file reading from resolver");
            Lwt.return_unit
          | Ok (`Data cs) ->
            process cs
        end
      | `Tls flow ->
        begin
          TLS.read flow >>= function
          | Error e ->
            t.flow <- None;
            Log.err (fun m -> m "error %a reading from resolver" TLS.pp_error e);
            Lwt.return_unit
          | Ok `Eof ->
            t.flow <- None;
            Log.info (fun m -> m "end of file reading from resolver");
            Lwt.return_unit
          | Ok (`Data cs) ->
            process cs
        end

    let query_one flow data =
      match flow with
      | `Plain flow ->
        begin
          S.TCP.write flow data >>= function
          | Error e ->
            Lwt.return (Error (`Msg (Fmt.to_to_string S.TCP.pp_write_error e)))
          | Ok () -> Lwt.return (Ok ())
        end
      | `Tls flow ->
        begin
          TLS.write flow data >>= function
          | Error e ->
            Lwt.return (Error (`Msg (Fmt.to_to_string TLS.pp_write_error e)))
          | Ok () -> Lwt.return (Ok ())
        end

    let req_all flow t =
      IM.fold (fun _id (data, _) r ->
          r >>= function
          | Error _ as e -> Lwt.return e
          | Ok () -> query_one flow data)
        t.requests (Lwt.return (Ok ()))

    let to_pairs =
      List.map (function `Plaintext (ip, port) | `Tls (_, ip, port) -> ip, port)

    let find_ns ns (addr, port) =
      List.find (function `Plaintext (ip, p) | `Tls (_, ip, p) ->
          Ipaddr.compare ip addr = 0 && p = port)
        ns

    let rec connect_ns t nameservers =
      let waiter, notify = Lwt.task () in
      let waiters, id = Happy_eyeballs.Waiter_map.register notify t.waiters in
      t.waiters <- waiters;
      let ns = to_pairs nameservers in
      let he, actions = Happy_eyeballs.connect_ip t.he (clock ()) ~id ns in
      t.he <- he;
      Lwt_condition.signal t.timer_condition ();
      Lwt.async (fun () -> Lwt_list.iter_p (handle_action t) actions);
      waiter >>= function
      | Error `Msg msg ->
        Log.err (fun m -> m "error connecting to resolver %s" msg);
        Lwt.return (Error (`Msg "connect failure"))
      | Ok (addr, flow) ->
        let continue flow =
          t.flow <- Some flow;
          Lwt.async (fun () ->
              read_loop t flow >>= fun () ->
              if not (IM.is_empty t.requests) then
                connect_ns t t.nameservers >|= function
                | Error `Msg msg ->
                  Log.err (fun m -> m "error while connecting to resolver: %s" msg)
                | Ok () -> ()
              else
                Lwt.return_unit);
          req_all flow t
        in
        let config = find_ns t.nameservers addr in
        match config with
        | `Plaintext _ -> continue (`Plain flow)
        | `Tls (tls_cfg, _ip, _port) ->
          TLS.client_of_flow tls_cfg flow >>= function
          | Ok tls -> continue (`Tls tls)
          | Error e ->
            Log.warn (fun m -> m "error establishing TLS connection to %a:%d: %a"
                         Ipaddr.pp (fst addr) (snd addr) TLS.pp_write_error e);
            let ns' =
              List.filter (function
                  | `Tls (_, ip, port) ->
                    not (Ipaddr.compare ip (fst addr) = 0 && port = snd addr)
                  | _ -> true)
                nameservers
            in
            if ns' = [] then
              Lwt.return (Error (`Msg "no further nameservers configured"))
            else
              connect_ns t ns'

    let connect t =
      match t.flow with
      | Some _ -> Lwt.return (Ok t)
      | None ->
        connect_ns t t.nameservers >|= function
        | Ok () -> Ok t
        | Error `Msg msg -> Error (`Msg msg)

    let close _f =
      (* ignoring this here *)
      Lwt.return_unit

    let send_recv t tx =
      if Cstruct.length tx > 4 then
        match t.flow with
        | None -> Lwt.return (Error (`Msg "no connection to resolver"))
        | Some flow ->
          let id = Cstruct.BE.get_uint16 tx 2 in
          with_timeout t.timeout_ns
            (let open Lwt_result.Infix in
             query_one flow tx >>= fun () ->
             let cond = Lwt_condition.create () in
             t.requests <- IM.add id (tx, cond) t.requests;
             let open Lwt.Infix in
             Lwt_condition.wait cond >|= fun data ->
             match data with Ok _ | Error `Msg _ as r -> r) >|= fun r ->
          t.requests <- IM.remove id t.requests;
          r
      else
        Lwt.return (Error (`Msg "invalid context (data length <= 4)"))

  end

  include Dns_client.Make(Transport)
end
