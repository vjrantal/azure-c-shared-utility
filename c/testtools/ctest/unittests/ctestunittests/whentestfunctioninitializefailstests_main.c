// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "ctest.h"

int main()
{
    size_t failedTests = 0;

    CTEST_RUN_TEST_SUITE(whentestfunctioninitializefailstests, failedTests);
    failedTests -= 2; /*the expected return is 2 failed test cases*/
    return failedTests;
}
