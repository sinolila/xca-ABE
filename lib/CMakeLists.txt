list(APPEND xcadoc_sources arguments.cpp arguments.h xcadoc.cpp)
list(APPEND xcaexport_sources pki_export.cpp pki_export.h xcaexport.cpp)

list(APPEND xcalib_sources
BioByteArray.cpp	dbhistory.cpp		pki_key.cpp
BioByteArray.h		dbhistory.h		pki_key.h
Passwd.cpp		entropy.cpp		pki_lookup.h
Passwd.h		entropy.h		pki_multi.cpp
arguments.cpp		exception.h		pki_multi.h
arguments.h		func.cpp		pki_pkcs12.cpp
asn1int.cpp		func.h			pki_pkcs12.h
asn1int.h		headerlist.h		pki_pkcs7.cpp
asn1time.cpp		ipvalidator.h		pki_pkcs7.h
asn1time.h		load_obj.cpp		pki_scard.cpp
base.h			load_obj.h		pki_scard.h
builtin_curves.cpp	pki_temp.cpp
builtin_curves.h	pki_temp.h
database_model.cpp	oid.cpp			pki_x509.cpp
database_model.h	oid.h			pki_x509.h
db_base.cpp		opensc-pkcs11.h		pki_x509req.cpp
db_base.h		openssl_compat.h	pki_x509req.h
db_crl.cpp		pass_info.cpp		pki_x509super.cpp
db_crl.h		pass_info.h		pki_x509super.h
db_key.cpp		pk11_attribute.cpp	settings.cpp
db_key.h		pk11_attribute.h	settings.h
db_temp.cpp		pkcs11.cpp		sql.cpp
db_temp.h		pkcs11.h		sql.h
db_token.cpp		pkcs11_lib.cpp		version.cpp
db_token.h		pkcs11_lib.h		x509name.cpp
db_x509.cpp		pki_base.cpp		x509name.h
db_x509.h		pki_base.h		x509rev.cpp
db_x509req.cpp		pki_crl.cpp		x509rev.h
db_x509req.h		pki_crl.h		x509v3ext.cpp
db_x509super.cpp	pki_evp.cpp		x509v3ext.h
db_x509super.h		pki_evp.h		xfile.h
dhgen.cpp		dhgen.h			XcaProgress.cpp
XcaProgress.h		XcaWarningCore.cpp	XcaWarningCore.h
PwDialogCore.cpp	PwDialogCore.h		digest.h
digest.cpp		pki_export.cpp		debug_info.h
func_base.cpp		func_base.h		debug_info.cpp
cmdline.cpp  db_sm9.cpp db_sm9.h
)

macro(ExpandSources target)
  list(TRANSFORM ${target}_sources PREPEND ${PROJECT_SOURCE_DIR}/lib/)
  list(APPEND ${target} ${PROJECT_BINARY_DIR}/local.h)
  target_sources(${target} PRIVATE ${${target}_sources})
endmacro()

ExpandSources(xcalib)
ExpandSources(xcadoc)
ExpandSources(xcaexport)

macro(Test name)
  set(${name}_sources ${ARGN})
  add_executable(${name} ${name}.cpp)
  ExpandSources(${name})
  target_link_libraries(${name} PRIVATE
    OpenSSL::Crypto ${QT}::Core ${QT}::Test ${QT}::Sql ${ASAN_LIB}
  )
  add_test(NAME ${name} COMMAND ${name})
  set_target_properties(${name} PROPERTIES MACOSX_BUNDLE FALSE)
  add_dependencies(tests ${name})
  set_tests_properties(${name} PROPERTIES LABELS "console;lib")
endmacro()

if(BUILD_TESTING)
  Test(test_biobytearray BioByteArray.cpp BioByteArray.h
                                    func_base.cpp func_base.h)
  Test(test_asn1int asn1int.cpp asn1int.h func_base.h func_base.cpp)
  Test(test_asn1time asn1time.cpp asn1time.h func_base.h func_base.cpp)
  Test(test_entropy entropy.cpp entropy.h func.h func_base.cpp xfile.h)
  Test(test_x509name x509name.cpp x509name.h func_base.h func_base.cpp
                                    BioByteArray.h BioByteArray.cpp )
  Test(test_digest digest.cpp digest.h func_base.cpp func_base.h)
endif()

# �����򻯰�SM9���Գ���
add_executable(sm9_simple_test ${PROJECT_SOURCE_DIR}/lib/test_sm9_simple.cpp)
target_link_libraries(sm9_simple_test PRIVATE
  ${QT}::Core
)
set_target_properties(sm9_simple_test PROPERTIES 
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)