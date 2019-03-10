
#ifndef ST_APP_TEMP_TEST_H
#define ST_APP_TEMP_TEST_H

#include "trust-schema-tests-def.h"

#include "../../ndn-lite/encode/name.h"
#include "../../ndn-lite/ndn-error-code.h"
#include "../../ndn-lite/security/ndn-trust-schema.h"
#include "../../ndn-lite/encode/trust-schema/ndn-trust-schema-pattern-component.h"
#include "../../ndn-lite/encode/trust-schema/ndn-trust-schema-pattern.h"
#include "../../ndn-lite/encode/trust-schema/ndn-trust-schema-rule.h"
#include "../../ndn-lite/encode/ndn-rule-storage.h"
#include "../../ndn-lite/encode/signed-interest.h"
#include "../../ndn-lite/encode/interest.h"
#include "../../ndn-lite/encode/data.h"
#include "../../ndn-lite/security/ndn-lite-ecc.h"

#include "../../ndn-lite/util/re.h"

#define st_test_app_name "st_test_app"

#define SECP160R1_PUB_KEY_SIZE 40
#define SECP160R1_PRV_KEY_SIZE 21
#define CURVE_TYPE (NDN_ECDSA_CURVE_SECP160R1)

#define valid_command_name_string "/ndn/SD/Yu/print/hello_world"
#define valid_identity_string "/ndn/admin"

#define invalid_command_name_string "/ndn/SD/YU/print/hello_world"
#define invalid_identity_string "/ndn/not_admin"

#define valid_interest_name_string "/random/interest/name"
#define valid_interest_identity_string "/random/identity"

void run_test_st_app(void);

#endif // ST_APP_TEMP_TEST_H
