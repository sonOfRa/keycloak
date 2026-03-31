/*
 * Copyright 2024 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.organization.utils;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OrganizationsTest {

    @Test
    void emailHasPlusLocalPart_nullEmail_returnsFalse() {
        assertFalse(Organizations.emailHasPlusLocalPart(null));
    }

    @Test
    void emailHasPlusLocalPart_noAtSign_returnsFalse() {
        assertFalse(Organizations.emailHasPlusLocalPart("notanemail"));
    }

    @Test
    void emailHasPlusLocalPart_noPlus_returnsFalse() {
        assertFalse(Organizations.emailHasPlusLocalPart("user@example.com"));
    }

    @Test
    void emailHasPlusLocalPart_plusInLocalPart_returnsTrue() {
        assertTrue(Organizations.emailHasPlusLocalPart("user+tag@example.com"));
    }

    @Test
    void emailHasPlusLocalPart_plusAfterAt_returnsFalse() {
        assertFalse(Organizations.emailHasPlusLocalPart("user@exam+ple.com"));
    }

    @Test
    void emailHasPlusLocalPart_multiplePlusInLocalPart_returnsTrue() {
        assertTrue(Organizations.emailHasPlusLocalPart("user+a+b@example.com"));
    }

    @Test
    void emailHasPlusLocalPart_plusAtStartOfLocalPart_returnsTrue() {
        assertTrue(Organizations.emailHasPlusLocalPart("+user@example.com"));
    }
}
