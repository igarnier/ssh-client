type ssh_session

type ssh_channel

type ssh_scp


type ssh_auth =
  | SSH_AUTH_SUCCESS
  | SSH_AUTH_DENIED
  | SSH_AUTH_PARTIAL
  | SSH_AUTH_INFO
  | SSH_AUTH_AGAIN
  | SSH_AUTH_ERROR (* == -1 /!\ *)

let ssh_auth_to_string = function
  | SSH_AUTH_SUCCESS -> "SSH_AUTH_SUCCESS"
  | SSH_AUTH_DENIED  -> "SSH_AUTH_DENIED"
  | SSH_AUTH_PARTIAL -> "SSH_AUTH_PARTIAL"
  | SSH_AUTH_INFO    -> "SSH_AUTH_INFO"
  | SSH_AUTH_AGAIN   -> "SSH_AUTH_AGAIN"
  | SSH_AUTH_ERROR   -> "SSH_AUTH_ERROR"


type ssh_error_code =
  | SSH_OK
  | SSH_ERROR
  | SSH_AGAIN
  | SSH_EOF

let ssh_error_code_to_string = function
  | SSH_OK    -> "SSH_OK"
  | SSH_ERROR -> "SSH_ERROR"
  | SSH_AGAIN -> "SSH_AGAIN"
  | SSH_EOF   -> "SSH_EOF"


(* | SSH_UNKNOWN (this is not a libssh code) *)

type ssh_verbosity =
  | SSH_LOG_NOLOG
  | SSH_LOG_WARNING
  | SSH_LOG_PROTOCOL
  | SSH_LOG_PACKET
  | SSH_LOG_FUNCTIONS

(* DO /NOT/ CHANGE THE ORDER OF THESE VARIANTS!!!! *)
type ssh_option =
  | SSH_OPTIONS_HOST of string
  | SSH_OPTIONS_PORT of int
  | SSH_OPTIONS_PORT_STR of string
  | SSH_OPTIONS_FD of int
  | SSH_OPTIONS_USER of string
  | SSH_OPTIONS_SSH_DIR of string
  | SSH_OPTIONS_IDENTITY of string
  | SSH_OPTIONS_ADD_IDENTITY of string
  | SSH_OPTIONS_KNOWNHOSTS of string
  | SSH_OPTIONS_TIMEOUT of int
  | SSH_OPTIONS_TIMEOUT_USEC of int
  | SSH_OPTIONS_SSH1 of bool
  | SSH_OPTIONS_SSH2 of bool
  | SSH_OPTIONS_LOG_VERBOSITY of ssh_verbosity
  | SSH_OPTIONS_LOG_VERBOSITY_STR of string
  | SSH_OPTIONS_CIPHERS_C_S of string
  | SSH_OPTIONS_CIPHERS_S_C of string
  | SSH_OPTIONS_COMPRESSION_C_S of string
  | SSH_OPTIONS_COMPRESSION_S_C of string
  | SSH_OPTIONS_PROXYCOMMAND of string
  | SSH_OPTIONS_BINDADDR of string
  | SSH_OPTIONS_STRICTHOSTKEYCHECK of bool
  | SSH_OPTIONS_COMPRESSION of string
  | SSH_OPTIONS_COMPRESSION_LEVEL of int
  | SSH_OPTIONS_KEY_EXCHANGE of string
  | SSH_OPTIONS_HOSTKEYS of string
  | SSH_OPTIONS_GSSAPI_SERVER_IDENTITY of string
  | SSH_OPTIONS_GSSAPI_CLIENT_IDENTITY of string
  | SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS of bool
  (* | SSH_OPTIONS_HMAC_C_S
   * | SSH_OPTIONS_HMAC_S_C *)


type ssh_scp_mode =
  | SSH_SCP_WRITE
  | SSH_SCP_READ
  | SSH_SCP_WRITE_RECURSIVE
  | SSH_SCP_READ_RECURSIVE

type ssh_scp_request =
  | SSH_SCP_REQUEST_NEWDIR  (*A new directory is going to be pulled*)
  | SSH_SCP_REQUEST_NEWFILE (* A new file is going to be pulled *)
  | SSH_SCP_REQUEST_EOF     (* End of requests *)
  | SSH_SCP_REQUEST_ENDDIR  (* End of directory *)
  | SSH_SCP_REQUEST_WARNING (* Warning received *)
  | SSH_SCP_REQUEST_ERROR   (* SSH error *)

let ssh_verbosity_to_string = function
  | SSH_LOG_NOLOG     -> "SSH_LOG_NOLOG"
  | SSH_LOG_WARNING   -> "SSH_LOG_WARNING"
  | SSH_LOG_PROTOCOL  -> "SSH_LOG_PROTOCOL"
  | SSH_LOG_PACKET    -> "SSH_LOG_PACKET"
  | SSH_LOG_FUNCTIONS -> "SSH_LOG_FUNCTIONS"

let ssh_option_to_string =
  let pr = Printf.sprintf in
  function
  | SSH_OPTIONS_HOST s -> pr "SSH_OPTIONS_HOST(%s)" s
  | SSH_OPTIONS_PORT i -> pr "SSH_OPTIONS_PORT(%d)"i
  | SSH_OPTIONS_PORT_STR s -> pr "SSH_OPTIONS_PORT_STR(%s)" s
  | SSH_OPTIONS_FD i -> pr "SSH_OPTIONS_FD(%d)"i
  | SSH_OPTIONS_USER s -> pr "SSH_OPTIONS_USER(%s)" s
  | SSH_OPTIONS_SSH_DIR s -> pr "SSH_OPTIONS_SSH_DIR(%s)" s
  | SSH_OPTIONS_IDENTITY s -> pr "SSH_OPTIONS_IDENTITY(%s)" s
  | SSH_OPTIONS_ADD_IDENTITY s -> pr "SSH_OPTIONS_ADD_IDENTITY(%s)" s
  | SSH_OPTIONS_KNOWNHOSTS s -> pr "SSH_OPTIONS_KNOWNHOSTS(%s)" s
  | SSH_OPTIONS_TIMEOUT i -> pr "SSH_OPTIONS_TIMEOUT(%d)" i
  | SSH_OPTIONS_TIMEOUT_USEC i -> pr "SSH_OPTIONS_TIMEOUT_USEC(%d)" i
  | SSH_OPTIONS_SSH1 b -> pr "SSH_OPTIONS_SSH1(%B)" b
  | SSH_OPTIONS_SSH2 b -> pr "SSH_OPTIONS_SSH2(%B)" b
  | SSH_OPTIONS_LOG_VERBOSITY v ->
      pr "SSH_OPTIONS_LOG_VERBOSITY of(%s)" (ssh_verbosity_to_string v)
  | SSH_OPTIONS_LOG_VERBOSITY_STR s -> pr "SSH_OPTIONS_LOG_VERBOSITY_STR(%s)" s
  | SSH_OPTIONS_CIPHERS_C_S s -> pr "SSH_OPTIONS_CIPHERS_C_S(%s)" s
  | SSH_OPTIONS_CIPHERS_S_C s -> pr "SSH_OPTIONS_CIPHERS_S_C(%s)" s
  | SSH_OPTIONS_COMPRESSION_C_S s -> pr "SSH_OPTIONS_COMPRESSION_C_S(%s)" s
  | SSH_OPTIONS_COMPRESSION_S_C s -> pr "SSH_OPTIONS_COMPRESSION_S_C(%s)" s
  | SSH_OPTIONS_PROXYCOMMAND s -> pr "SSH_OPTIONS_PROXYCOMMAND(%s)" s
  | SSH_OPTIONS_BINDADDR s -> pr "SSH_OPTIONS_BINDADDR(%s)" s
  | SSH_OPTIONS_STRICTHOSTKEYCHECK b -> pr "SSH_OPTIONS_STRICTHOSTKEYCHECK(%B)" b
  | SSH_OPTIONS_COMPRESSION s -> pr "SSH_OPTIONS_COMPRESSION(%s)" s
  | SSH_OPTIONS_COMPRESSION_LEVEL i -> pr "SSH_OPTIONS_COMPRESSION_LEVEL(%d)" i
  | SSH_OPTIONS_KEY_EXCHANGE s -> pr "SSH_OPTIONS_KEY_EXCHANGE(%s)" s
  | SSH_OPTIONS_HOSTKEYS s -> pr "SSH_OPTIONS_HOSTKEYS(%s)" s
  | SSH_OPTIONS_GSSAPI_SERVER_IDENTITY s -> pr "SSH_OPTIONS_GSSAPI_SERVER_IDENTITY(%s)" s
  | SSH_OPTIONS_GSSAPI_CLIENT_IDENTITY s -> pr "SSH_OPTIONS_GSSAPI_CLIENT_IDENTITY(%s)" s
  | SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS b -> pr "SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS(%B)" b