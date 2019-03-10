
#include "st-app-temp-test.h"

#include "yu-prnt-cmd-chk.h"

static ndn_interest_t valid_command_interest;
static ndn_interest_t invalid_command_interest;
static ndn_name_t valid_identity;
static ndn_name_t invalid_identity;

static ndn_interest_t valid_interest;

ndn_ecc_pub_t pub_key;
ndn_ecc_prv_t prv_key;

const char pref[] = "In run_test_st_app, ";

static const uint8_t pub_key_val[SECP160R1_PUB_KEY_SIZE] = {
  0xA1, 0x2B, 0xBF, 0x14, 0x77, 0x58, 0x51, 0xFD, 0xFF, 0x03, 
  0xAA, 0x5C, 0x88, 0x6E, 0xD5, 0xCB, 0xA4, 0xAA, 0x01, 0x0A, 
  0x04, 0x79, 0xFD, 0xF2, 0xF0, 0x9C, 0x81, 0x2B, 0x8A, 0xCA, 
  0xAA, 0x6D, 0x08, 0x84, 0xD0, 0xC2, 0xF0, 0x23, 0x6E, 0x37
};

static const uint8_t prv_key_val[SECP160R1_PRV_KEY_SIZE] = {
  0x00, 
  0x96, 0xC6, 0x5F, 0x59, 0x87, 0x62, 0xB9, 0x81, 0x2E, 0xE8, 
  0xEF, 0xAB, 0x7B, 0xB4, 0x4F, 0x74, 0x45, 0x88, 0x16, 0xD5
};

int init_test_objects(void) {
  
  int ret_val = -1;

  ret_val = init_yu_prnt_cmd_chk();
  if (ret_val != 0) {
    printf("%sinit_yu_prnt_cmd_chk failed, error code: %d\n", pref, ret_val);
    return ret_val;
  }
  
  ret_val = ndn_name_from_string(&valid_identity, valid_identity_string, sizeof(valid_identity_string));
  if (ret_val != 0) {
    printf("%sndn_name_from_string failed, error code: %d.\n", pref, ret_val);
    return ret_val;
  }  
  ret_val = ndn_name_from_string(&invalid_command_interest.name, invalid_command_name_string, sizeof(invalid_command_name_string));
  if (ret_val != 0) {
    printf("%sndn_name_from_string failed, error code: %d.\n", pref, ret_val);
    return ret_val;
  }
  ret_val = ndn_name_from_string(&invalid_identity, invalid_identity_string, sizeof(invalid_identity_string));
  if (ret_val != 0) {
    printf("%sndn_name_from_string failed, error code: %d.\n", pref, ret_val);
    return ret_val;
  }
  ret_val = ndn_name_from_string(&valid_interest.name, valid_interest_name_string, sizeof(valid_interest_name_string));
  if (ret_val != 0) {
    printf("%sndn_name_from_string_failed, error code: %d\n", pref, ret_val);
    return ret_val;
  }
  ret_val = ndn_name_from_string(&valid_command_interest.name, valid_command_name_string, sizeof(valid_command_name_string));
  if (ret_val != 0) {
    printf("%sndn_name_from_string failed, error code: %d.\n", pref, ret_val);
    return ret_val;
  }

  printf("name of valid command interest after compilation (number of name components: %d):\n", valid_command_interest.name.components_size);
  for (uint32_t i = 0; i < valid_command_interest.name.components_size; i++) {
    printf("/%.*s", valid_command_interest.name.components[i].size, valid_command_interest.name.components[i].value);
  }
  printf("\n");


  ret_val = ndn_ecc_prv_init(&prv_key, prv_key_val, sizeof(prv_key_val), CURVE_TYPE, 1234);
  if (ret_val != 0) {
    printf("%sndn_ecc_prv_init failed, error code: %d\n", pref, ret_val);
    return ret_val;
  }

  ret_val = ndn_ecc_pub_init(&pub_key, pub_key_val, sizeof(pub_key_val), CURVE_TYPE, 1234);
  if (ret_val != 0) {
    printf("%sndn_ecc_pub_init failed, error code: %d\n", pref, ret_val);
    return ret_val;
  }

  ret_val = ndn_signed_interest_ecdsa_sign(&invalid_command_interest, &invalid_identity, &prv_key);
  if (ret_val != 0) {
    printf("%sndn_signed_interest_ecdsa_sign failed, error ocde: %d\n", pref, ret_val);
    return ret_val;
  }

  ret_val = ndn_signed_interest_ecdsa_sign(&valid_interest, &invalid_identity, &prv_key);
  if (ret_val != 0) {
    printf("%sndn_signed_interest_ecdsa_sign failed, error ocde: %d\n", pref, ret_val);
    return ret_val;
  }
  
  ret_val = ndn_signed_interest_ecdsa_sign(&valid_command_interest, &valid_identity, &prv_key);
  if (ret_val != 0) {
    printf("%sndn_signed_interest_ecdsa_sign failed, error code: %d\n", pref, ret_val);
    return ret_val;
  }
  
  printf("name of valid command interest after signing (number of name components: %d):\n", valid_command_interest.name.components_size);
  for (uint32_t i = 0; i < valid_command_interest.name.components_size; i++) {
    printf("/%.*s", valid_command_interest.name.components[i].size, valid_command_interest.name.components[i].value);
  }
  printf("\n");
  

  return 0;
  
}

void run_test_st_app(void) {

  printf("This is an application using the schematized trust implementation of ndn-lite\n\n");

  ndn_security_init();
  
  int ret_val = -1;

  ret_val = init_test_objects();
  if (ret_val != 0) {
    printf("%sinitialization of test objects failed, error code: %d\n", pref, ret_val);
    return;
  }

  printf("\n---\n\n");

  ret_val = check_interest(&valid_command_interest, &yu_rule, &pub_key);
  if (ret_val == 0) {
    printf("%scheck_interest_against_rule succeeded for valid command interest; this is the expected behavior, good.\n", pref);
  }
  else {
    printf("%scheck_interest_against_rule failed for valid command interest, this is unexpected behavior, error code: %d\n", pref, ret_val);
    return;
  }

  printf("\n---\n\n");

  ret_val = check_interest(&invalid_command_interest, &yu_rule, &pub_key);
  if (ret_val == 0) {
    printf("%scheck_interest_against_rule succeeded for invalid command interest, this is unexpected behavior, error code: %d\n", pref, ret_val);
    return;
  }
  else {
    printf("%scheck_interest_against_rule failed for invalid command interest, this is expected behavior, good (error code: %d).\n", pref, ret_val);
  }

  printf("\n---\n\n");

  ret_val = check_interest(&valid_interest, &yu_rule, &pub_key);
  if (ret_val == 0) {
    printf("%scheck_interest_against_rule succeeded for valid non-yu-printing-command interest; this is the expected behavior, good.\n", pref);
  }
  else {
    printf("%scheck_interest_against_rule failed for valid non-yu-printing-command interest, this is unexpected behavior, error code: %d\n", pref, ret_val);
    return;
  }
  
}

