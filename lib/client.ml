open Types

type auth =
  | Auto        (** Authenticate using the Ssh agent, assuming its running *)
  | Interactive (** Type in the password on the command line*)

type options = { host: string;
                 username : string;
                 port : int;
                 log_level : ssh_verbosity;
                 auth : auth
               }

exception InternalError of string

external connect_and_auth : options -> ssh_session -> unit = "libssh_ml_ssh_connect_and_auth"

external exec : command:string -> ssh_session -> string = "libssh_ml_ssh_exec"

let carriage_return s =
  if s.[String.length s - 1] = '\r' then
    s
  else
    s^"\r"

external unsafe_scp :
  string ->
  string ->
  string ->
  int ->
  ssh_session ->
  unit = "libssh_ml_ssh_scp"

(* let with_session f opts =
 *   let handle = init () in
 *   connect opts handle;
 *   let res = f handle in
 *   close handle;
 *   res *)

let check_else msg res =
  match res with
  | SSH_OK ->
    Printf.eprintf "%s: success\n%!" msg
  | _ ->
    raise (InternalError msg)

let with_shell f session =
  let open Raw in
  let chan = Channel.new_ session in
  try
    check_else "Client.with_channel: open_session" (Channel.open_session chan);
    (* check_else "Client.with_channel: request_pty error" (Channel.request_pty chan);
     * check_else "Client.with_channel: change_pty_size error" (Channel.change_pty_size chan 80 80); *)
    check_else "Client.with_channel: request_shell" (Channel.request_shell chan);
    let result = match f chan with
      | exception exn ->
        (check_else "Client.with_channel: close" (Channel.close chan);
         raise exn)
      | v -> v
    in
    check_else "Client.with_channel: close" (Channel.close chan);
    Channel.free chan;
    result
  with
  | InternalError msg ->
    (Channel.free chan;
     failwith msg)
  | exn ->
    (Channel.free chan;
     raise exn)

let scp ~src_path ~base_path ~dst_filename ~mode h =
  if not @@ Sys.file_exists src_path then failwith "This file doesn't exist";
  unsafe_scp src_path base_path dst_filename mode h
