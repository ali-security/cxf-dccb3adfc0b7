/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.cxf.tools.wsdlto.jaxb;

import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.Permission;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.xml.XMLConstants;
import javax.xml.transform.dom.DOMSource;
import javax.xml.validation.SchemaFactory;

import org.w3c.dom.Element;

import org.xml.sax.SAXException;

import org.apache.cxf.common.xmlschema.SchemaCollection;
import org.apache.cxf.staxutils.StaxUtils;
import org.apache.cxf.tools.common.ToolException;
import org.apache.cxf.tools.wsdlto.databinding.jaxb.JAXBDataBinding;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * CVE-2026-49875: the {@link SchemaFactory} that {@link JAXBDataBinding#validateSchema} builds
 * (wsdl2java schema validation) had no JAXP hardening, so a schema reachable from the processed
 * WSDL could carry a DOCTYPE whose external entity was resolved out of band. Its resource
 * resolver also answered entity lookups, and resources it returns are exempt from the parser's
 * secure processing restrictions, so it must refuse anything that is not a schema document.
 */
public class JAXBDataBindingValidateSchemaTest {

    private static final String CANARY_NAME = "xxe-canary.txt";
    private static final String IMPORTED_NS = "http://xxe.test/imported";

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    /** The hardening must not stop the tool from loading the schemas a WSDL imports. */
    @Test
    public void testImportedSchemaIsStillValidated() throws Exception {
        File dir = tmp.newFolder();
        write(new File(dir, "imported.xsd"), schema(IMPORTED_NS, "imported", ""));
        String systemId = new File(dir, "main.xsd").toURI().toString();

        new JAXBDataBinding().validateSchema(mainSchema("imported.xsd"), systemId, null,
                                             new SchemaCollection());
    }

    /**
     * Feeds the validation an import that resolves to an attacker controlled schema carrying a
     * DOCTYPE with an external entity. The control pass proves the payload really does trigger
     * the out-of-band fetch through an unhardened schema factory; the second pass proves
     * {@code validateSchema} no longer performs it.
     */
    @Test
    public void testExternalEntityInImportedSchemaIsNotResolved() throws Exception {
        File dir = tmp.newFolder();
        File canary = write(new File(dir, CANARY_NAME), "cxf-xxe-canary");
        write(new File(dir, "evil.xsd"),
              "<?xml version=\"1.0\"?>"
              + "<!DOCTYPE xs:schema [<!ENTITY xxe SYSTEM \"" + canary.toURI() + "\">]>"
              + schema(IMPORTED_NS, "evil",
                       "<xs:annotation><xs:documentation>&xxe;</xs:documentation></xs:annotation>"));
        String systemId = new File(dir, "main.xsd").toURI().toString();
        JAXBDataBinding dataBinding = new JAXBDataBinding();

        try (CanaryReadRecorder recorder = new CanaryReadRecorder()) {
            // control: an unconfigured SchemaFactory happily fetches the external entity
            try {
                SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI)
                    .newSchema(new DOMSource(mainSchema("evil.xsd"), systemId));
            } catch (SAXException ex) {
                // the payload does not have to produce a usable schema, only to be fetched
            }
            assertTrue("the payload does not reproduce the XXE, so the test proves nothing",
                       recorder.canaryWasRead());
            recorder.clear();

            // the shipped code path must not fetch anything
            try {
                dataBinding.validateSchema(mainSchema("evil.xsd"), systemId, null, new SchemaCollection());
            } catch (ToolException ex) {
                // rejecting the DOCTYPE bearing schema is a perfectly good outcome
            }
            assertFalse("the external entity was resolved - XXE is still possible: " + recorder.reads,
                        recorder.canaryWasRead());
        }
    }

    private static File write(File file, String content) throws IOException {
        Files.write(file.toPath(), content.getBytes(StandardCharsets.UTF_8));
        return file;
    }

    private static String schema(String targetNamespace, String element, String body) {
        return "<xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\""
            + " targetNamespace=\"" + targetNamespace + "\" elementFormDefault=\"qualified\">"
            + body
            + "<xs:element name=\"" + element + "\" type=\"xs:string\"/>"
            + "</xs:schema>";
    }

    private static Element mainSchema(String importLocation) throws Exception {
        String xml = "<xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\""
            + " targetNamespace=\"http://xxe.test/main\" elementFormDefault=\"qualified\">"
            + "<xs:import namespace=\"" + IMPORTED_NS + "\" schemaLocation=\"" + importLocation + "\"/>"
            + "<xs:element name=\"root\" type=\"xs:string\"/>"
            + "</xs:schema>";
        return StaxUtils.read(new StringReader(xml)).getDocumentElement();
    }

    /**
     * Installs a fully permissive SecurityManager that only records attempts to read the canary,
     * so an external entity fetch leaves a trace that the test can assert on, offline.
     */
    private static final class CanaryReadRecorder extends SecurityManager implements AutoCloseable {
        private final List<String> reads = new CopyOnWriteArrayList<>();
        private final SecurityManager previous;

        CanaryReadRecorder() {
            previous = System.getSecurityManager();
            System.setSecurityManager(this);
        }

        boolean canaryWasRead() {
            return !reads.isEmpty();
        }

        void clear() {
            reads.clear();
        }

        @Override
        public void close() {
            System.setSecurityManager(previous);
        }

        @Override
        public void checkPermission(Permission perm) {
        }

        @Override
        public void checkPermission(Permission perm, Object context) {
        }

        @Override
        public void checkRead(String file) {
            record(file);
        }

        @Override
        public void checkRead(String file, Object context) {
            record(file);
        }

        private void record(String file) {
            if (file != null && file.endsWith(CANARY_NAME)) {
                reads.add(file);
            }
        }
    }
}
