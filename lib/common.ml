
(* #define SSH_OK 0     /* No error */
 * #define SSH_ERROR -1 /* Error of some kind */
 * #define SSH_AGAIN -2 /* The nonblocking call must be repeated */
 * #define SSH_EOF -127 /* We have already a eof */ *)



   
    (* We are in the parent, wait on the child to send the result *)    
    
  (*   ) in
   * let pid   = Netmcore_process.start fp () in
   * let r_opt = Netmcore_process.join jp pid in
   * match r_opt with
   * | None ->
   *   failwith "Ssh.Common.with_session: error while executing client child process"
   * | Some result ->
   *   result *)
