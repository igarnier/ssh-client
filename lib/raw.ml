open Types

external version : unit -> string = "libssh_ml_version"

module Userauth =
struct

  external password : ssh_session -> string -> string -> ssh_auth = "libssh_ml_ssh_userauth_password"

end

module Session =
struct

  (* raises Failure in case of error *)
  external new_ : unit -> ssh_session = "libssh_ml_ssh_new"

  external connect : ssh_session -> ssh_error_code = "libssh_ml_ssh_connect"

  external disconnect : ssh_session -> ssh_error_code = "libssh_ml_ssh_disconnect"

  external close : ssh_session -> unit = "libssh_ml_ssh_close"

  external options_set : ssh_session -> ssh_option -> ssh_error_code = "libssh_ml_ssh_options_set"

end

module Channel =
struct

  (** Raises "Failure" in case of error *)
  external new_ : ssh_session -> ssh_channel = "libssh_ml_ssh_channel_new"

  (** Does not raise (except bug) *)
  external close : ssh_channel -> ssh_error_code = "libssh_ml_ssh_channel_close"

  (** Does not raise (except bug) *)  
  external free : ssh_channel -> unit = "libssh_ml_ssh_channel_free"

  (** Does not raise (except bug) *)    
  external open_session : ssh_channel -> ssh_error_code = "libssh_ml_ssh_channel_open_session"

  (** Can raise exception "Failure" *)
  external request_exec : ssh_channel -> string -> ssh_error_code = "libssh_ml_ssh_channel_request_exec"

  (** Does not raise *)
  external request_pty : ssh_channel -> ssh_error_code = "libssh_ml_ssh_channel_request_pty"

  (** Does not raise *)  
  external change_pty_size : ssh_channel -> int -> int -> ssh_error_code = "libssh_ml_channel_ssh_change_pty_size"

  (** Does not raise *)  
  external request_shell : ssh_channel -> ssh_error_code = "libssh_ml_ssh_channel_request_shell"      

  (** Can raise exception "Failure" *)
  external read_timeout : ssh_channel -> bool -> int -> string = "libssh_ml_channel_read_timeout"

  (** Can raise exception "Failure" *)
  external write : ssh_channel -> string -> ssh_error_code = "libssh_ml_ssh_channel_write"

  (** Does not raise *)  
  external send_eof : ssh_channel -> ssh_error_code = "libssh_ml_ssh_channel_send_eof"

end

module Scp =
struct

  external accept_request : ssh_scp -> ssh_error_code = "libssh_ml_scp_accept_request"

  external close : ssh_scp -> ssh_error_code = "libssh_ml_scp_close"

  external deny_request : ssh_scp -> string -> ssh_error_code = "libssh_ml_scp_deny_request"

  external free : ssh_scp -> unit = "libssh_ml_scp_free"

  external init : ssh_scp -> ssh_error_code = "libssh_ml_scp_init"

  external leave_directory : ssh_scp -> ssh_error_code = "libssh_ml_scp_leave_directory"

  external new_ : ssh_session -> ssh_scp_mode -> string -> ssh_scp = "libssh_ml_ssh_scp_new"

  external pull_request : ssh_scp -> ssh_scp_request = "libssh_ml_ssh_scp_pull_request"

  external push_directory : ssh_scp -> string -> int -> ssh_error_code = "libssh_ml_ssh_scp_push_directory"

  external push_file : ssh_scp -> string -> int -> int -> ssh_error_code = "libssh_ml_ssh_scp_push_file"

  external push_file64 : ssh_scp -> string -> int64 -> int -> ssh_error_code = "libssh_ml_ssh_scp_push_file"
  
end
