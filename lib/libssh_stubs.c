// C Standard stuff
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <assert.h>
// OCaml declarations
#include <caml/mlvalues.h>
#include <caml/alloc.h>
#include <caml/memory.h>
#include <caml/fail.h>
#include <caml/callback.h>
// libssh itself
#include <libssh/libssh.h>
#include <libssh/sftp.h>

#define BUFFERSIZE 256

// a table to convert from SSH session error codes to variant tags
#define ML_SSH_OK 0
#define ML_SSH_ERROR 1
#define ML_SSH_AGAIN 2
#define ML_SSH_EOF 3
// #define ML_SSH_UNKNOWN 4 (this is not a libssh code)

#define return_sess_rc(_m) do {\
     switch(_m) {\
     case SSH_OK:\
          CAMLreturn(Val_int(ML_SSH_OK));\
          break;\
     case SSH_ERROR:\
          CAMLreturn(Val_int(ML_SSH_ERROR));\
          break;\
     case SSH_AGAIN:\
          CAMLreturn(Val_int(ML_SSH_AGAIN));\
          break;\
     case SSH_EOF:\
          CAMLreturn(Val_int(ML_SSH_EOF));\
          break;\
     default:\
          fprintf(stderr, "__FUNCTION__: unknown session errcode");\
          abort();\
          break;\
     }\
} while(0)


// converting ssh auth error codes to variant tags
#define ML_SSH_AUTH_SUCCESS 0
#define ML_SSH_AUTH_DENIED 1
#define ML_SSH_AUTH_PARTIAL 2
#define ML_SSH_AUTH_INFO 3
#define ML_SSH_AUTH_AGAIN 4
#define ML_SSH_AUTH_ERROR 5

#define return_auth_rc(_m) do {\
     switch(_m) {\
     case SSH_AUTH_SUCCESS:\
          CAMLreturn(Val_int(ML_SSH_AUTH_SUCCESS));\
          break;\
     case SSH_AUTH_DENIED:\
          CAMLreturn(Val_int(ML_SSH_AUTH_DENIED));\
          break;\
     case SSH_AUTH_PARTIAL:\
          CAMLreturn(Val_int(ML_SSH_AUTH_PARTIAL));\
          break;\
     case SSH_AUTH_INFO:\
          CAMLreturn(Val_int(ML_SSH_AUTH_INFO));\
          break;\
     case SSH_AUTH_AGAIN:\
          CAMLreturn(Val_int(ML_SSH_AUTH_AGAIN));\
          break;\
     case SSH_AUTH_ERROR:\
          CAMLreturn(Val_int(ML_SSH_AUTH_ERROR));\
          break;\
     default:\
          fprintf(stderr, "__FUNCTION__: unknown auth errcode");\
          abort();\
          break;\
     }\
} while(0)


// converting ssh scp modes to variant tags
#define ML_SSH_SCP_WRITE 0
#define ML_SSH_SCP_READ 1
#define ML_SSH_SCP_WRITE_RECURSIVE 2
#define ML_SSH_SCP_READ_RECURSIVE 3


// TODO: This has to go.
struct result { int status; char *output; };

/** Functions related to userauth */

CAMLprim value libssh_ml_ssh_userauth_password(value session, value username, value password)
{
     CAMLparam3(session, username, password);

     ssh_session sess = (ssh_session) session;
     
     char* cusrname = caml_strdup(String_val(username));
     char* cpasswd  = caml_strdup(String_val(password));

     const int rc = ssh_userauth_password(sess, cusrname, cpasswd);

     caml_stat_free(cusrname);
     caml_stat_free(cpasswd);     

     return_auth_rc(rc);
}

/** Functions related to sessions */

CAMLprim value libssh_ml_ssh_new(void)
{
     CAMLparam0();
     ssh_session sess = ssh_new();

     if(!sess) {
          caml_failwith("Couldn't initiate ssh session");
     }

     CAMLreturn((value) sess);
}

CAMLprim value libssh_ml_ssh_connect(value session)
{
     CAMLparam1(session);

     ssh_session sess = (ssh_session) session;
     
     const int rc = ssh_connect(sess);

     return_sess_rc(rc);
}

CAMLprim value libssh_ml_ssh_disconnect(value session)
{
     CAMLparam1(session);

     ssh_session sess = (ssh_session) session;

     ssh_disconnect(sess);

     CAMLreturn(Val_unit);
}

CAMLprim value libssh_ml_ssh_close(value session)
{
     CAMLparam1(session);

     ssh_session sess = (ssh_session) session;
     
     ssh_disconnect(sess);

     ssh_free(sess);
     
     CAMLreturn(Val_unit);
}

CAMLprim value libssh_ml_ssh_options_set(value session, value option)
{
     CAMLparam2(session, option);
     CAMLlocal1(field);

     char* cstr = NULL;
     int   intv = 0;
     int   rc   = 0;
     int   tag  = 0;
     ssh_session sess = (ssh_session) session;

     assert(Is_block(option));

     tag = Tag_val(option);

     switch(tag) {
     case SSH_OPTIONS_HOST:
     case SSH_OPTIONS_PORT_STR:
     case SSH_OPTIONS_USER:
     case SSH_OPTIONS_SSH_DIR:
     case SSH_OPTIONS_IDENTITY:
     case SSH_OPTIONS_ADD_IDENTITY:
     case SSH_OPTIONS_KNOWNHOSTS:
     case SSH_OPTIONS_LOG_VERBOSITY_STR:
     case SSH_OPTIONS_CIPHERS_C_S:
     case SSH_OPTIONS_CIPHERS_S_C:
     case SSH_OPTIONS_COMPRESSION_C_S:
     case SSH_OPTIONS_COMPRESSION_S_C:
     case SSH_OPTIONS_PROXYCOMMAND:
     case SSH_OPTIONS_BINDADDR:
     case SSH_OPTIONS_COMPRESSION:          
     case SSH_OPTIONS_KEY_EXCHANGE:
     case SSH_OPTIONS_HOSTKEYS:
     case SSH_OPTIONS_GSSAPI_SERVER_IDENTITY:
     case SSH_OPTIONS_GSSAPI_CLIENT_IDENTITY:
          // String case
          field = Field(option, 0);
          cstr  = caml_strdup(String_val(field));
          rc = ssh_options_set(sess, tag, cstr);
          caml_stat_free(cstr);
          break;

     case SSH_OPTIONS_PORT:
     case SSH_OPTIONS_FD:
     case SSH_OPTIONS_TIMEOUT:
     case SSH_OPTIONS_TIMEOUT_USEC:
     case SSH_OPTIONS_COMPRESSION_LEVEL:
          // Integer case
          field = Field(option, 0);
          intv  = Int_val(field);
          rc = ssh_options_set(sess, tag, &intv);
          break;
     
     case SSH_OPTIONS_SSH1:
     case SSH_OPTIONS_SSH2:
     case SSH_OPTIONS_STRICTHOSTKEYCHECK:
     case SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS:
          // Boolean case
          field = Field(option, 0);
          intv  = Bool_val(field);
          rc =ssh_options_set(sess, tag, &intv);
          break;
          
     case SSH_OPTIONS_LOG_VERBOSITY:
          // ssh_verbosity case
          field = Field(option, 0);
          intv  = Int_val(field);
          rc = ssh_options_set(sess, tag, &intv);
          break;

     default:
          caml_failwith("libssh_ml_ssh_options_set: unknown tag");
     }

     return_sess_rc(rc);
}


/** Functions related to channels */

CAMLprim value libssh_ml_ssh_channel_new(value session)
{
     CAMLparam1(session);

     ssh_channel channel = ssh_channel_new((ssh_session) session);

     if(!channel) {
          caml_failwith("Couldn't allocate ssh channel");
     }

     CAMLreturn((value) channel);
}

CAMLprim value libssh_ml_ssh_channel_close(value channel)
{
     CAMLparam1(channel);

     const int rc = ssh_channel_close((ssh_channel) channel);

     return_sess_rc(rc);
}

CAMLprim value libssh_ml_ssh_channel_free(value channel)
{
     CAMLparam1(channel);

     ssh_channel_free((ssh_channel) channel);

     CAMLreturn(Val_unit);
}

CAMLprim value libssh_ml_ssh_channel_open_session(value channel)
{
     CAMLparam1(channel);
     
     const int rc = ssh_channel_open_session((ssh_channel) channel);

     return_sess_rc(rc);
}

CAMLprim value libssh_ml_ssh_channel_request_exec(value channel, value cmd)
{
     CAMLparam2(channel, cmd);

     char* command = caml_strdup(String_val(cmd));

     const int rc  = ssh_channel_request_exec((ssh_channel) channel, command);

     caml_stat_free(command);

     return_sess_rc(rc);
}

CAMLprim value libssh_ml_ssh_channel_request_pty(value channel)
{
     CAMLparam1(channel);

     const int rc = ssh_channel_request_pty((ssh_channel) channel);

     return_sess_rc(rc);
}

CAMLprim value libssh_ml_ssh_channel_change_pty_size(value channel, value x, value y)
{
     CAMLparam3(channel, x, y);

     const int rc = ssh_channel_change_pty_size((ssh_channel) channel, Int_val(x), Int_val(y));

     return_sess_rc(rc);
}

CAMLprim value libssh_ml_ssh_channel_request_shell(value channel)
{
     CAMLparam1(channel);

     const int rc = ssh_channel_request_shell((ssh_channel) channel);

     return_sess_rc(rc);
}

int read_until_empty(ssh_channel channel, char** output, int timeout, int is_stderr)
{
     // int  polled     = 0;     // bytes available for reading
     char buffer[BUFFERSIZE]; // temp buffer
     int  nbytes     = 0;     // #bytes read during the last ssh_channel_read
     int  nread      = 0;     // effectively read bytes = allocated size of *output
     // int  outputsize = 0;     // allocated bytes
     int  rc         = 0;     // return code for ssh_channel_read
     
     if(*output) {
          caml_failwith("read_until_empty: output pointer should be initially NULL");
     }

     while((nbytes = ssh_channel_read_timeout(channel, buffer, BUFFERSIZE, is_stderr, timeout)) > 0) {          

          if(nbytes < 0) {
               // error
               return rc;
          }

          // increase length of *output by nbytes
          *output = caml_stat_resize(*output, nread + nbytes);
          
          // copy from buffer to *output
          strncpy(*output + nread, buffer, nbytes);
          
          nread += nbytes;
     }

     *output = caml_stat_resize(*output, nread + 1);
     (*output)[nread] = '\0';

     return nread;
     
}

CAMLprim value libssh_ml_channel_read_timeout(value channel, value is_stderr, value timeout)
{
     CAMLparam3(channel, is_stderr, timeout);
     CAMLlocal1(output_val);

     ssh_channel chan   = (ssh_channel) channel;
     char*       output = NULL;

     const int to = Int_val(timeout);
     const int rc = read_until_empty(chan, &output, to, Bool_val(is_stderr));

     if(rc < 0) {
          caml_stat_free(output);
          ssh_channel_close((ssh_channel) chan);
          ssh_channel_free((ssh_channel) chan);
          caml_failwith("libssh_ml_channel_read: internal error");
     } else if(rc == 0) {
          output_val = caml_alloc_string(0);
          caml_stat_free(output);
          CAMLreturn(output_val);          
     } else {
          // make output null-terminated
          output_val = caml_copy_string(output);
          caml_stat_free(output);
          CAMLreturn(output_val);
     }
     
}

/* CAMLprim value libssh_ml_channel_read(value channel) */
/* { */
/*      CAMLparam1(channel); */
/*      CAMLlocal1(output_val); */

/*      char* output = NULL; */
/*      int   nbytes = 0, nread = 0, outputsize = 0; */
/*      char  buffer[BUFFERSIZE]; */

/*      ssh_channel chan = (ssh_channel) channel; */
     
/*      output = caml_stat_alloc(BUFFERSIZE); */
/*      outputsize = BUFFERSIZE; */
     
/*      while ((nbytes = ssh_channel_read(chan, buffer, BUFFERSIZE, 0)) > 0) { */

/*           if ((nread + nbytes) > outputsize) { */
/*                output = caml_stat_resize(output, outputsize + BUFFERSIZE); */
/*                outputsize += BUFFERSIZE; */
/*           } */
          
/*           strncpy((output + nread), buffer, nbytes); */
/*           nread += nbytes; */
/*      } */

/*      if(nbytes == SSH_ERROR) { */
/*           // TODO: something better, e.g. return a string Result.t */
/*           caml_stat_free(output); */
/*           ssh_channel_close(chan); */
/*           ssh_channel_free(chan); */
/*           caml_failwith("Error while reading channel"); */
/*      } */
     
/*      output = caml_stat_resize(output, nread + 1); */
/*      output[nread] = '\0'; */

/*      output_val = caml_copy_string(output); */
/*      caml_stat_free(output); */

/*      CAMLreturn(output_val); */
/* } */

CAMLprim value libssh_ml_ssh_channel_write(value channel, value data)
{
     CAMLparam2(channel, data);

     const int len = caml_string_length(data);
     char* cdata   = caml_strdup(String_val(data));

     const int rc  = ssh_channel_write((ssh_channel) channel, cdata, len);
     
     caml_stat_free(cdata);
     
     if(rc < 0) {
          return_sess_rc(rc);
     } else {
          CAMLreturn(Val_int(ML_SSH_OK));
     }
}

CAMLprim value libssh_ml_ssh_channel_send_eof(value channel)
{
     CAMLparam1(channel);
     
     const int rc = ssh_channel_send_eof((ssh_channel) channel);

     return_sess_rc(rc);
}


/** scp-related bindings */

CAMLprim value libssh_ml_scp_accept_request(value scp)
{
     CAMLparam1(scp);
     
     const int rc = ssh_scp_accept_request((ssh_scp) scp);

     return_sess_rc(rc);
}

CAMLprim value libssh_ml_scp_close(value scp)
{
     CAMLparam1(scp);
     
     const int rc = ssh_scp_close((ssh_scp) scp);

     return_sess_rc(rc);
}

CAMLprim value libssh_ml_scp_deny_request(value scp, value reason)
{
     CAMLparam2(scp, reason);

     char* c_reason = caml_strdup(String_val(reason));
     
     const int rc = ssh_scp_deny_request((ssh_scp) scp, c_reason);

     caml_stat_free(c_reason);
 
     return_sess_rc(rc);
}

CAMLprim value libssh_ml_scp_free(value scp)
{
     CAMLparam1(scp);
     
     ssh_scp_free((ssh_scp) scp);

     CAMLreturn(Val_unit);
}


CAMLprim value libssh_ml_scp_init(value scp)
{
     CAMLparam1(scp);
     
     const int rc = ssh_scp_init((ssh_scp) scp);

     return_sess_rc(rc);
}

CAMLprim value libssh_ml_scp_leave_directory(value scp)
{
     CAMLparam1(scp);
     
     const int rc = ssh_scp_leave_directory((ssh_scp) scp);

     return_sess_rc(rc);
}

CAMLprim value libssh_ml_ssh_scp_new(value session, value mode, value location)
{
     CAMLparam3(session, mode, location);
     
     ssh_session sess = (ssh_session) session;
     char* c_location = caml_strdup(String_val(location));
     int c_mode = 0;
     ssh_scp result = NULL;

     switch(Int_val(mode)) {
     case ML_SSH_SCP_WRITE:
          c_mode = SSH_SCP_WRITE;
          break;
     case ML_SSH_SCP_READ:
          c_mode = SSH_SCP_READ;
          break;
     case ML_SSH_SCP_WRITE_RECURSIVE:
          c_mode = SSH_SCP_WRITE | SSH_SCP_RECURSIVE;
          break;
     case ML_SSH_SCP_READ_RECURSIVE:
          c_mode = SSH_SCP_READ | SSH_SCP_RECURSIVE;
          break;
     default:
          caml_stat_free(c_location);
          caml_failwith("libssh_ml_ssh_scp_new: wrong mode");
     }

     result = ssh_scp_new(sess, c_mode, c_location);

     caml_stat_free(c_location);
     
     if(!result) {
          caml_failwith("Could not allocate initiate scp session");
     }

     CAMLreturn((value) result);
}

CAMLprim value libssh_ml_ssh_scp_pull_request(value scp)
{
     CAMLparam1(scp);
     CAMLlocal1(output_val);
    
     const int rc = ssh_scp_pull_request((ssh_scp) scp);
     int caml_tag = -1;

     // the cases below and the caml_tag should match the order of tag declaration in types.ml
     switch(rc) {
     case SSH_SCP_REQUEST_NEWDIR:
          caml_tag = 0;
          break;          
     case SSH_SCP_REQUEST_NEWFILE:
          caml_tag = 1;
          break;
     case SSH_SCP_REQUEST_EOF:
          caml_tag = 2;
          break;          
     case SSH_SCP_REQUEST_ENDDIR:
          caml_tag = 3;
          break;          
     case SSH_SCP_REQUEST_WARNING:
          caml_tag = 4;
          break;          
     case SSH_ERROR:
          caml_tag = 5;
          break;          
     default:
          caml_failwith("libssh_ml_ssh_scp_pull_request: unexpected return code");
     }

     output_val = Val_int(caml_tag);

     CAMLreturn(output_val);
}

CAMLprim value libssh_ml_ssh_scp_push_directory(value scp, value dirname, value mode)
{
     CAMLparam3(scp, dirname, mode);

     char* c_dirname = caml_strdup(String_val(dirname));

     const int c_mode = Int_val(mode);
     
     const int rc = ssh_scp_push_directory((ssh_scp) scp, c_dirname, c_mode);
     
     caml_stat_free(c_dirname);

     return_sess_rc(rc);
}

CAMLprim value libssh_ml_ssh_scp_push_file(value scp, value filename, value size, value mode)
{
     CAMLparam4(scp, filename, size, mode);
     
     char* c_filename = caml_strdup(String_val(filename));

     const size_t c_size = Int_val(size);

     const int c_mode = Int_val(mode);

     const int rc = ssh_scp_push_file((ssh_scp) scp, c_filename, c_size, c_mode);

     caml_stat_free(c_filename);

     return_sess_rc(rc);     
}


CAMLprim value libssh_ml_ssh_scp_push_file64(value scp, value filename, value size, value mode)
{
     CAMLparam4(scp, filename, size, mode);
     
     char* c_filename = caml_strdup(String_val(filename));

     const uint64_t c_size = Int64_val(size);

     const int c_mode = Int_val(mode);
     
     const int rc = ssh_scp_push_file64((ssh_scp) scp, c_filename, c_size, c_mode);

     caml_stat_free(c_filename);

     return_sess_rc(rc);     
}

/* bindings unimplemented */
/* LIBSSH_API int ssh_scp_read(ssh_scp scp, void *buffer, size_t size); */
CAMLprim value libssh_ml_ssh_scp_read(value scp, value buffer)
{
     CAMLparam2(scp, buffer);

     const int len = caml_string_length(buffer);


     const int rc = ssh_scp_read((ssh_scp) scp, (void*) String_val(buffer), len);

     if(rc == SSH_ERROR) {
          caml_failwith("libssh_ml_ssh_scp_read: error");
     } else {
          CAMLreturn(Val_int(rc));
     }

}

CAMLprim value libssh_ml_ssh_scp_request_get_filename(value scp)
{
     CAMLparam1(scp);
     CAMLlocal1(str);

     const char* res = ssh_scp_request_get_filename((ssh_scp) scp);

     if(!res) {
          caml_failwith("libssh_ml_ssh_scp_request_get_filename: NULL filename");
     }

     str = caml_copy_string(res);

     CAMLreturn(str);
}


/* LIBSSH_API int ssh_scp_request_get_permissions(ssh_scp scp); */
/* LIBSSH_API size_t ssh_scp_request_get_size(ssh_scp scp); */
/* LIBSSH_API uint64_t ssh_scp_request_get_size64(ssh_scp scp); */
/* LIBSSH_API const char *ssh_scp_request_get_warning(ssh_scp scp); */

CAMLprim value libssh_ml_ssh_scp_write(value scp, value buffer)
{
     CAMLparam2(scp, buffer);

     const int len = caml_string_length(buffer);

     const int rc = ssh_scp_write((ssh_scp) scp, (const void*) String_val(buffer), len);

     if(rc == SSH_ERROR) {
          caml_failwith("libssh_ml_ssh_scp_read: error");
     } else {
          CAMLreturn(Val_unit);
     }
}



/** Original libssh bindings (minus some bugs) */

CAMLprim value libssh_ml_version(void)
{
     return caml_copy_string(SSH_STRINGIFY(LIBSSH_VERSION));
}


void check_result(int r, ssh_session this_session)
{
     if (r != SSH_OK) {
          const char* error = ssh_get_error(this_session);
          fprintf(stderr, "Fatal error: %s\n", error);

          ssh_disconnect(this_session);
          ssh_free(this_session);

          caml_failwith("ssh error");
     }
}

static void verify_server(ssh_session this_sess)
{
     const int rc = ssh_is_server_known(this_sess);

     switch(rc) {
     case SSH_SERVER_KNOWN_OK:
          break;
     case SSH_SERVER_KNOWN_CHANGED:
          fprintf(stderr, "Remote server has changed the key. Possible attack. Aborting\n");
          exit(1);
          break;
     case SSH_SERVER_FOUND_OTHER:
          fprintf(stderr, "Type of key has changed. This is a possible attack. Aborting\n");
          exit(1);
          break;
     case SSH_SERVER_NOT_KNOWN:
          fprintf(stderr, "Unknown server. Continuing\n");
          // exit(1);
          break;
     case SSH_SERVER_FILE_NOT_FOUND:
          fprintf(stderr, "Host file not found. Aborting\n");
          exit(1);
          break;
     case SSH_SERVER_ERROR:
          fprintf(stderr, "SSH server error. Aborting\n");
          exit(1);
          break;
     default:
          fprintf(stderr, "verify_server: unknown error code %d. Aborting\n", rc);
          exit(1);
     }
}

static struct result exec_remote_command(char *this_command, ssh_session session)
{
     ssh_channel channel;
     int rc;
     char buffer[BUFFERSIZE];
     char *output;
     int nbytes;
     int nread = 0;
     int outputsize;

     channel = ssh_channel_new(session);

     if (channel == NULL) {                              
          return (struct result){SSH_ERROR, NULL};
     }
     
     rc = ssh_channel_open_session(channel);
     
     if (rc != SSH_OK) {
          ssh_channel_free(channel);
          return (struct result){rc, NULL};
     }
     
     rc = ssh_channel_request_exec(channel, this_command);

     if (rc != SSH_OK) {
          ssh_channel_close(channel);
          ssh_channel_free(channel);
          return (struct result){rc, NULL};
     }
     
     output = caml_stat_alloc(BUFFERSIZE);
     outputsize = BUFFERSIZE;
     
     while ((nbytes = ssh_channel_read(channel, buffer, BUFFERSIZE, 0)) > 0) {
          if ((nread + nbytes) > outputsize) {
               output = caml_stat_resize(output, outputsize + BUFFERSIZE);
               outputsize += BUFFERSIZE;
          }
          strncpy((output + nread), buffer, nbytes);
          nread += nbytes;
     }
     if (nbytes < 0) {
          caml_stat_free(output);
          ssh_channel_close(channel);
          ssh_channel_free(channel);
          return (struct result){SSH_ERROR, NULL};
     }

     ssh_channel_send_eof(channel);
     ssh_channel_close(channel);
     ssh_channel_free(channel);

     output = caml_stat_resize(output, nread + 1);
     output[nread] = '\0';
     return (struct result){SSH_OK, output};
}

CAMLprim value libssh_ml_ssh_exec(value command_val, value sess_val)
{
     CAMLparam2(command_val, sess_val);
     CAMLlocal1(output_val);

     char *command;
     size_t len;
     ssh_session this_sess;

     len = caml_string_length(command_val);
     command = caml_strdup(String_val(command_val));
     if (strlen(command) != len) {
          caml_failwith("Problem copying string from OCaml to C");
     }
     this_sess = (ssh_session)sess_val;

     struct result this_result = exec_remote_command(command, this_sess);

     caml_stat_free(command);

     output_val = caml_copy_string(this_result.output);

     free(this_result.output);

     CAMLreturn(output_val);
}

CAMLprim value libssh_ml_ssh_connect_and_auth(value opts, value sess_val)
{
     CAMLparam2(opts, sess_val);
     CAMLlocal5(hostname_val, username_val, port_val, log_level_val, auth_val);

     char *hostname, *username, *password;
     int port, log_level, auth;
     size_t len;
     ssh_session this_sess;

     this_sess = (ssh_session)sess_val;
     hostname_val = Field(opts, 0);
     username_val = Field(opts, 1);
     port_val = Field(opts, 2);
     log_level_val = Field(opts, 3);
     auth_val = Field(opts, 4);

     len = caml_string_length(hostname_val);
     hostname = caml_strdup(String_val(hostname_val));

     if (strlen(hostname) != len) {
          caml_failwith("Problem copying string from OCaml to C");
     } else len = 0;

     username = caml_strdup(String_val(username_val));
     len = caml_string_length(username_val);

     if (strlen(username) != len) {
          caml_failwith("Problem copying string from OCaml to C");
     } else len = 0;

     port = Int_val(port_val);
     log_level = Int_val(log_level_val);
     auth = Int_val(auth_val);

     check_result(ssh_options_set(this_sess, SSH_OPTIONS_HOST, hostname),
                  this_sess);

     check_result(ssh_options_set(this_sess, SSH_OPTIONS_PORT, &port),
                  this_sess);

     check_result(ssh_options_set(this_sess, SSH_OPTIONS_LOG_VERBOSITY, &log_level),
                  this_sess);

     check_result(ssh_options_set(this_sess, SSH_OPTIONS_USER, username),
                  this_sess);

     check_result(ssh_connect(this_sess), this_sess);
     verify_server(this_sess);

     switch (auth) {
     case 0:
          check_result(ssh_userauth_publickey_auto(this_sess, NULL, NULL), this_sess);
          break;
     case 1:
          password = getpass("\nEnter Password: ");
          if (ssh_userauth_password(this_sess, username, password) != SSH_AUTH_SUCCESS) {
               printf("Error: %s\n", ssh_get_error(this_sess));
          }
          printf("\n");
          free(password);
     }

     caml_stat_free(hostname);
     caml_stat_free(username);

     CAMLreturn(Val_unit);
}

CAMLprim value libssh_ml_remote_shell(value produce, value consume, value sess_val)
{
     CAMLparam3(produce, consume, sess_val);
     CAMLlocal1(exec_this);

     ssh_session this_sess = (ssh_session)sess_val;
     exec_this = caml_callback(produce, Val_unit);
     size_t len = caml_string_length(exec_this);
     char *copied = caml_strdup(String_val(exec_this));
     if (strlen(copied) != len) {
          caml_failwith("Problem copying string from OCaml to C");
     }

     struct result r = exec_remote_command(copied, this_sess);

     caml_callback(consume, caml_copy_string(r.output));
     caml_stat_free(copied);
     CAMLreturn(Val_unit);
}

static ssh_scp prepare(const char* base_path, ssh_session sess)
{
     ssh_scp scp;
     int result_code;

     scp = ssh_scp_new(sess, SSH_SCP_WRITE | SSH_SCP_RECURSIVE, base_path);
     if(!scp) {
          caml_failwith(ssh_get_error(sess));
     }
     result_code = ssh_scp_init(scp);
     check_result(result_code, sess);

     return scp;
}

CAMLprim value libssh_ml_ssh_scp(value src_path,
                                 value base_path,
                                 value dst_filename,
                                 value mode,
				 value sess)
{
     CAMLparam5(src_path, base_path, dst_filename, mode, sess);

     size_t len = 0;
     char *s_path = NULL, *b_path = NULL, *dst_fname;
     ssh_session this_sess;

     len = caml_string_length(src_path);
     s_path = caml_strdup(String_val(src_path));

     if (strlen(s_path) != len) {
          caml_failwith("Problem copying string from OCaml to C");
     }

     len = caml_string_length(base_path);
     b_path = caml_strdup(String_val(base_path));

     if (strlen(b_path) != len) {
          caml_failwith("Problem copying string from OCaml to C");
     }

     len = caml_string_length(dst_filename);
     dst_fname = caml_strdup(String_val(dst_filename));

     if (strlen(dst_fname) != len) {
          caml_failwith("Problem copying string from OCaml to C");
     }
     

     this_sess = (ssh_session)sess;

     ssh_scp this_scp = prepare(b_path, this_sess);
     
     struct stat file_info;

     if (stat(s_path, &file_info) != 0) {
          caml_failwith("Cannot get needed file information for scp");
     }

     /* open file to be copied */
     FILE *fd = fopen(s_path, "r");

     if(!fd) {
          fprintf(stderr, "Could not open file %s for reading.\n", s_path);

          caml_stat_free(s_path);
          caml_stat_free(b_path);
          caml_stat_free(dst_fname);

          caml_failwith("fopen failed");
     }

     /* allocate buffer for file to be stored */
     char *fbuff = caml_stat_alloc(file_info.st_size);
     
     /* copy file contents to local buffer */
     const size_t n = fread(fbuff, file_info.st_size, 1, fd);

     if(n != 1) {
          fprintf(stderr, "Error while copying data from %s: expected 1 chunk of %ld bytes, got %ld instead.\n", s_path, file_info.st_size, n);
          
          caml_stat_free(fbuff);
          fclose(fd);
          caml_stat_free(s_path);
          caml_stat_free(b_path);
          caml_stat_free(dst_fname);

          caml_failwith("Could not read data from source file for scp");
     }

     // fprintf(stderr, "Copied successfuly %ld bytes of data", file_info.st_size);

     const int push_code = ssh_scp_push_file(this_scp,
                                             dst_fname,
                                             file_info.st_size,
                                             Int_val(mode));

     // fprintf(stderr, "push_file: %d", (push_code == SSH_OK));

     const int write_code = ssh_scp_write(this_scp,
                                          fbuff,
                                          file_info.st_size);

     // fprintf(stderr, "write: %d", (write_code == SSH_OK));

     caml_stat_free(fbuff);
     fclose(fd);
     caml_stat_free(s_path);
     caml_stat_free(b_path);
     caml_stat_free(dst_fname);

     if(push_code == SSH_ERROR) {
          caml_failwith("scp_push_file failed");
     }

     if(write_code == SSH_ERROR) {
          caml_failwith("scp_write failed");
     }
    
     CAMLreturn(Val_unit);
}
