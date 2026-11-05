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

package org.apache.cxf.staxutils.validation;

import java.io.StringReader;
import java.lang.reflect.Field;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.xml.XMLConstants;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.transform.dom.DOMSource;

import org.w3c.dom.Element;

import com.sun.msv.reader.xmlschema.MultiSchemaReader;

import org.apache.cxf.staxutils.StaxUtils;
import org.apache.cxf.xxe.XXETestListener;
import org.codehaus.stax2.validation.XMLValidationSchema;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * CVE-2026-49875: {@link W3CMultiSchemaFactory} parsed the schemas it loads with the shared,
 * unhardened {@link SAXParserFactory} of Woodstox's {@code BaseSchemaFactory}, so a schema pulled
 * in while loading a service's schemas could carry a DOCTYPE whose external entity was resolved
 * out of band.
 */
public class W3CMultiSchemaFactoryTest {

    private static final String DISALLOW_DOCTYPE_DECL_FEATURE =
        "http://apache.org/xml/features/disallow-doctype-decl";

    private static final String SIMPLE_SCHEMA =
        "<xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\""
        + " targetNamespace=\"http://xxe.test/main\" elementFormDefault=\"qualified\">"
        + "<xs:element name=\"root\" type=\"xs:string\"/>"
        + "</xs:schema>";

    @Test
    public void testSaxParserFactoryIsHardened() throws Exception {
        W3CMultiSchemaFactory factory = new W3CMultiSchemaFactory();
        Map<String, EmbeddedSchema> sources = new LinkedHashMap<>();
        sources.put("http://xxe.test/main",
                    new EmbeddedSchema("http://xxe.test/main.xsd", parse(SIMPLE_SCHEMA)));

        // the hardening must not get in the way of loading ordinary schemas
        XMLValidationSchema schema = factory.loadSchemas("http://xxe.test/", sources);
        assertNotNull("a plain schema could no longer be loaded", schema);

        SAXParserFactory parserFactory = parserFactoryOf(factory);
        assertNotNull("no SAXParserFactory was created", parserFactory);
        assertTrue("FEATURE_SECURE_PROCESSING was not enabled",
                   parserFactory.getFeature(XMLConstants.FEATURE_SECURE_PROCESSING));
        assertTrue("DOCTYPE declarations are still accepted",
                   parserFactory.getFeature(DISALLOW_DOCTYPE_DECL_FEATURE));
    }

    /**
     * Feeds the schema loader an import that resolves to an attacker controlled schema carrying
     * a DOCTYPE with an external entity. The control pass proves the payload really does trigger
     * the out-of-band fetch when the parser is left unhardened; the second pass proves the
     * shipped code no longer performs it.
     */
    @Test
    public void testExternalEntityInImportedSchemaIsNotResolved() throws Exception {
        try (XXETestListener listener = new XXETestListener()) {
            Path evil = listener.write("evil.xsd", maliciousSchema(listener.canaryUri()));
            String main =
                "<xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\""
                + " targetNamespace=\"http://xxe.test/main\" elementFormDefault=\"qualified\">"
                + "<xs:import namespace=\"http://xxe.test/evil\" schemaLocation=\""
                + listener.uriOf(evil) + "\"/>"
                + "<xs:element name=\"root\" type=\"xs:string\"/>"
                + "</xs:schema>";
            String baseUri = listener.directoryUri();
            Element mainElement = parse(main);
            Map<String, EmbeddedSchema> sources = new LinkedHashMap<>();
            sources.put("http://xxe.test/main", new EmbeddedSchema(baseUri + "main.xsd", mainElement));

            // control: the pre-fix configuration (a plain namespace aware factory, which is all
            // BaseSchemaFactory.getSaxFactory() ever provided) does fetch the canary
            SAXParserFactory unhardened = SAXParserFactory.newInstance();
            unhardened.setNamespaceAware(true);
            parseWith(unhardened, baseUri, sources);
            assertTrue("the payload does not reproduce the XXE, so the test proves nothing",
                       listener.canaryWasRead());
            listener.clear();

            // the shipped code must refuse the DOCTYPE before anything is fetched
            W3CMultiSchemaFactory factory = new W3CMultiSchemaFactory();
            try {
                factory.loadSchemas(baseUri, sources);
            } catch (Exception ex) {
                // rejecting the DOCTYPE bearing import is a perfectly good outcome
            }
            assertNotNull("loadSchemas never configured a parser", parserFactoryOf(factory));
            assertFalse("the external entity was resolved - XXE is still possible: " + listener.reads(),
                        listener.canaryWasRead());
        }
    }

    private static String maliciousSchema(String canaryUri) {
        return "<?xml version=\"1.0\"?>"
            + "<!DOCTYPE xs:schema [<!ENTITY xxe SYSTEM \"" + canaryUri + "\">]>"
            + "<xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\""
            + " targetNamespace=\"http://xxe.test/evil\" elementFormDefault=\"qualified\">"
            + "<xs:annotation><xs:documentation>&xxe;</xs:documentation></xs:annotation>"
            + "<xs:element name=\"evil\" type=\"xs:string\"/>"
            + "</xs:schema>";
    }

    /** Mirrors what {@code W3CMultiSchemaFactory.loadSchemas} does, minus the hardening. */
    private static void parseWith(SAXParserFactory parserFactory, String baseUri,
                                  Map<String, EmbeddedSchema> sources) {
        ResolvingGrammarReaderController controller =
            new ResolvingGrammarReaderController(baseUri, sources);
        MultiSchemaReader reader = new MultiSchemaReader(
            new W3CMultiSchemaFactory.RecursiveAllowedXMLSchemaReader(controller, parserFactory));
        try {
            for (EmbeddedSchema source : sources.values()) {
                DOMSource domSource = new DOMSource(source.getSchemaElement());
                domSource.setSystemId(source.getSystemId());
                reader.parse(domSource);
            }
            reader.getResult();
        } catch (Exception ex) {
            // the control pass only cares about what was fetched
        }
    }

    private static Element parse(String xml) throws Exception {
        return StaxUtils.read(new StringReader(xml)).getDocumentElement();
    }

    private static SAXParserFactory parserFactoryOf(W3CMultiSchemaFactory factory) throws Exception {
        Field field = W3CMultiSchemaFactory.class.getDeclaredField("parserFactory");
        field.setAccessible(true);
        return (SAXParserFactory)field.get(factory);
    }
}
