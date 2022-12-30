set(CPACK_PACKAGE_NAME "gmssl")
set(CPACK_PACKAGE_VENDOR "GmSSL develop team")
set(CPACK_PACKAGE_VERSION_MAJOR 3)
set(CPACK_PACKAGE_VERSION_MINOR 0)
set(CPACK_PACKAGE_VERSION_PATCH 0)
set(CPACK_PACKAGE_DESCRIPTION_FILE ${PROJECT_SOURCE_DIR}/README.md)
string(CONCAT CPACK_PACKAGE_DESCRIPTION_SUMMARY 
    "GmSSL is an open source cryptographic toolbox that supports SM2 / SM3 / SM4 / SM9 "
    "and other national secret (national commercial password) algorithm. ")
set(CPACK_RESOURCE_FILE_LICENSE "${PROJECT_SOURCE_DIR}/LICENSE")
set(CPACK_PACKAGE_INSTALL_DIRECTORY /usr)
set(CPACK_PACKAGE_CONTACT "https://github.com/guanzhi/GmSSL/issues")
# The general number of package itself. 
# Should be incremented when the package content changes for the same version.
# Can be used to distinguish between different builds of the same version.
# Can be overridden by `cmake -DCPACK_NOARCH_PACKAGE_RELEASE=1`
set(CPACK_NOARCH_PACKAGE_RELEASE 1 CACHE STRING "The general release number of package")
