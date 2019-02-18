#include <sgx_urts.h>
#include <boost/program_options.hpp>
#include <stdexcept>

#include "enclave-utils.h"

#include <pwd.h>
#include <fstream>
#include <iostream>
#include <vector>

#define MAX_PATH FILENAME_MAX

/* Check error conditions for loading enclave */
std::string get_sgx_error_msg(sgx_status_t ret)
{
  size_t idx = 0;
  size_t ttl = sizeof sgx_errlist / sizeof sgx_errlist[0];

  std::stringstream ss;

  for (idx = 0; idx < ttl; idx++) {
    if (ret == sgx_errlist[idx].err) {
      if (NULL != sgx_errlist[idx].sug) {
        ss << "Info: " << sgx_errlist[idx].sug << ". ";
      }

      ss << "Error: " << sgx_errlist[idx].msg;
      break;
    }
  }

  if (idx == ttl) {
    ss << "Error: Unexpected error " << ret;
  }

  return ss.str();
}

int initialize_enclave(sgx_enclave_id_t *eid)
{
  return initialize_enclave(ENCLAVE_FILENAME, eid);
}

int initialize_enclave(std::string enclave_path, sgx_enclave_id_t *eid)
{
  char token_path[MAX_PATH] = {'\0'};
  sgx_launch_token_t token = {0};
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  int updated = 0;

  /* Step 1: retrive the launch token saved by last transaction */
  /* try to get the token saved in $HOME */
  const char *home_dir = getpwuid(getuid())->pw_dir;
  if (home_dir != NULL && (strlen(home_dir) + strlen("/") +
                           sizeof(TOKEN_FILENAME) + 1) <= MAX_PATH) {
    /* compose the token path */
    strncpy(token_path, home_dir, strlen(home_dir));
    strncat(token_path, "/", strlen("/"));
    strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME) + 1);
  } else {
    /* if token path is too long or $HOME is NULL */
    strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
  }

  FILE *fp = fopen(token_path, "rb");
  if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
    printf(
        "Warning: Failed to create/open the launch token file \"%s\".\n",
        token_path);
  }

  if (fp != NULL) {
    /* read the token from saved file */
    size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
    if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
      /* if token is invalid, clear the buffer */
      memset(&token, 0x0, sizeof(sgx_launch_token_t));
      printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
    }
  }

  /* Step 2: call sgx_create_enclave to initialize an enclave instance */
  /* Debug Support: set 2nd parameter to 1 */
  ret = sgx_create_enclave(
      enclave_path.c_str(), SGX_DEBUG_FLAG, &token, &updated, eid, NULL);
  if (ret != SGX_SUCCESS) {
    printf(
        "sgx_create_enclave returned %#x\n (%s)",
        ret,
        get_sgx_error_msg(ret).c_str());
    if (fp != NULL) fclose(fp);
    return -1;
  }

  /* Step 3: save the launch token if it is updated */
  if (updated == 0 || fp == NULL) {
    /* if the token is not updated, or file handler is invalid, do not perform
     * saving */
    if (fp != NULL) fclose(fp);
    return 0;
  }

  /* reopen the file with write capablity */
  fp = freopen(token_path, "wb", fp);
  if (fp == NULL) return 0;
  size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
  if (write_num != sizeof(sgx_launch_token_t))
    printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
  fclose(fp);
  return 0;
}

int ocall_print_to_std(const char *str)
{
  /* Proxy/Bridge will check the length and null-terminate
   * the input string to prevent buffer overflow.
   */
  int ret = printf("%s", str);
  fflush(stdout);
  return ret;
}

int ocall_print_to_err(const char *str)
{
  /* Proxy/Bridge will check the length and null-terminate
   * the input string to prevent buffer overflow.
   */
  int ret = fprintf(stderr, "%s", str);
  fflush(stdout);
  return ret;
}

std::vector<uint8_t> readBinaryFile(const std::string &fname)
{
  std::ifstream in(fname, std::ios_base::binary);
  if (!in.is_open()) {
    throw std::invalid_argument("cannot open file " + fname);
  }

  return std::vector<uint8_t>(
      std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

std::string readTextFile(const std::string &fname)
{
  std::ifstream in(fname);
  if (!in.is_open()) {
    throw std::invalid_argument("cannot open file " + fname);
  }

  return std::string(
      std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}