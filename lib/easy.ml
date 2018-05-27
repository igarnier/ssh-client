open Batteries

open Types

type log_level =
  | SSH_LOG_NOLOG
  | SSH_LOG_WARNING
  | SSH_LOG_PROTOCOL
  | SSH_LOG_PACKET
  | SSH_LOG_FUNCTIONS

type auth =
  | Auto
  | Interactive

type options = { host      : string;
                 username  : string;
                 port      : int;
                 log_level : log_level;
                 auth      : auth
               }

let with_session : (ssh_session -> 'a) -> 'a  =
  fun f ->
    (* output/input are from the POV of the ancestor, i.e.
       children write on the input and the ancestor reads the output *)
    let output, input = Unix.pipe () in  
    let this_pid      = Unix.fork () in
    if this_pid < 0 then
      failwith "Easy.with_session: error while forking"
    else if this_pid = 0 then begin
      let ssh_session = Raw.Session.init () in
      let res = f ssh_session in
      Raw.Session.close ssh_session;
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
          Printf.sprintf "Easy.with_session: abnormal termination of child process (code %d)" n
        in
        failwith m
      | WSIGNALED n ->
        let m =
          Printf.sprintf "Easy.with_session: abnormal termination of child process (signal %d)" n
        in
        failwith m      
      | WSTOPPED n ->
        let m =
          Printf.sprintf "Easy.with_session: abnormal termination of child process (stopped %d)" n
        in
        failwith m      
    end
