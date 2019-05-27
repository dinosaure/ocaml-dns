open Dns

let ( let* ) = Result.bind

(* used by DS, RFC 4034 section 5.1.4 *)
let digest algorithm owner dnskey =
  let* h =
    match algorithm with
    | Ds.SHA1 -> Ok `SHA1
    | Ds.SHA256 -> Ok `SHA256
    | Ds.SHA384 -> Ok `SHA384
    | dt ->
      Error (`Msg (Fmt.str "Unsupported hash algorithm %a"
                     Ds.pp_digest_type dt))
  in
  Ok (Mirage_crypto.Hash.digest h (Dnskey.digest_prep owner dnskey))

let dnskey_to_rsa cs =
  (* described in RFC 3110 *)
  let e_len = Cstruct.get_uint8 cs 0 in
  let e, n = Cstruct.split (Cstruct.shift cs 1) e_len in
  let e = Mirage_crypto_pk.Z_extra.of_cstruct_be e
  and n = Mirage_crypto_pk.Z_extra.of_cstruct_be n
  in
  Mirage_crypto_pk.Rsa.pub ~e ~n

let guard a e = if a then Ok () else Error e

let verify now key name rrsig rrmap =
  (* from RFC 4034 section 3.1.8.1 *)
  let* algorithm =
    match rrsig.Rrsig.algorithm with
    | Dnskey.RSA_SHA1 -> Ok `SHA1
    | Dnskey.RSA_SHA256 -> Ok `SHA256
    | Dnskey.RSA_SHA512 -> Ok `SHA512
    | a -> Error (`Msg (Fmt.str "unsupported signature algorithm %a"
                          Dnskey.pp_algorithm a))
  in
  let* () =
    guard (Ptime.is_later ~than:now rrsig.Rrsig.signature_expiration)
      (`Msg "signature timestamp expired")
  in
  let* () =
    guard (Ptime.is_later ~than:rrsig.Rrsig.signature_inception now)
      (`Msg "signature not yet incepted")
  in
  let hashp = (=) algorithm in
  let* data = Rr_map.prep_for_sig name rrsig rrmap in
  Cstruct.hexdump data;
  print_endline "signature";
  Cstruct.hexdump rrsig.Rrsig.signature;
  if Mirage_crypto_pk.Rsa.PKCS1.verify ~hashp ~key (`Message data) ~signature:rrsig.Rrsig.signature then
    Ok ()
  else
    Error (`Msg "failed to verify signature")
