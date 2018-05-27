open Batteries

type ssh_session

type ssh_channel

type error_code =
  | SSH_OK
  | SSH_ERROR
  | SSH_AGAIN
  | SSH_EOF
  | SSH_UNKNOWN

(* #define SSH_OK 0     /* No error */
 * #define SSH_ERROR -1 /* Error of some kind */
 * #define SSH_AGAIN -2 /* The nonblocking call must be repeated */
 * #define SSH_EOF -127 /* We have already a eof */ *)

external version : unit -> string = "libssh_ml_version"

external init : unit -> ssh_session = "libssh_ml_ssh_init"

external connect : ssh_session -> error_code = "libssh_ml_ssh_connect"

external disconnect : ssh_session -> error_code = "libssh_ml_ssh_disconnect"

external close : ssh_session -> unit = "libssh_ml_ssh_close"
   
let with_session : (ssh_session -> 'a) -> 'a  =
  fun f ->
  (* output/input are from the POV of the ancestor, i.e.
     children write on the input and the ancestor reads the output *)
  let output, input = Unix.pipe () in  
  let this_pid      = Unix.fork () in
  if this_pid < 0 then
    failwith "Ssh.Common.with_session: error while forking"
  else if this_pid = 0 then begin
    let ssh_session = init () in
    let res = f ssh_session in
    close ssh_session;
    let input_chan = Unix.out_channel_of_descr input in
    BatMarshal.output input_chan res;
    close_out input_chan;
    exit 0
  end else begin
    Unix.close input;
    let _, status = Unix.wait () in
    match status with
    | WEXITED 0 ->
      Marshal.input (Unix.in_channel_of_descr output)
    | WEXITED n ->
      let m =
        Printf.sprintf "Ssh.Common.with_session: abnormal termination of child process (code %d)" n
      in
      failwith m
    | WSIGNALED n ->
      let m =
        Printf.sprintf "Ssh.Common.with_session: abnormal termination of child process (signal %d)" n
      in
      failwith m      
    | WSTOPPED n ->
      let m =
        Printf.sprintf "Ssh.Common.with_session: abnormal termination of child process (stopped %d)" n
      in
      failwith m      
  end
    (* We are in the parent, wait on the child to send the result *)    
    
  (*   ) in
   * let pid   = Netmcore_process.start fp () in
   * let r_opt = Netmcore_process.join jp pid in
   * match r_opt with
   * | None ->
   *   failwith "Ssh.Common.with_session: error while executing client child process"
   * | Some result ->
   *   result *)
