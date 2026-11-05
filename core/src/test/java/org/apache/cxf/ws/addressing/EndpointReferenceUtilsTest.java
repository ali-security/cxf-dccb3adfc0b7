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

package org.apache.cxf.ws.addressing;

import java.io.StringReader;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.xml.XMLConstants;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.w3c.dom.ls.LSInput;
import org.w3c.dom.ls.LSResourceResolver;

import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;
import org.xml.sax.SAXNotRecognizedException;
import org.xml.sax.SAXNotSupportedException;
import org.xml.sax.SAXParseException;

import org.apache.cxf.service.model.ServiceInfo;
import org.apache.cxf.xxe.XXETestListener;

import org.junit.After;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * CVE-2026-49875: {@code EndpointReferenceUtils.createSchema} built a {@link SchemaFactory}
 * without any JAXP hardening, so a schema document reaching it could resolve external entities
 * out of band.
 */
public class EndpointReferenceUtilsTest {

    private static final String FACTORY_PROPERTY =
        SchemaFactory.class.getName() + ":" + XMLConstants.W3C_XML_SCHEMA_NS_URI;

    private static final String DISALLOW_DOCTYPE_DECL_FEATURE =
        "http://apache.org/xml/features/disallow-doctype-decl";

    @After
    public void tearDown() {
        System.clearProperty(FACTORY_PROPERTY);
        RecordingSchemaFactory.reset();
    }

    @Test
    public void testSchemaFactoryIsHardened() {
        RecordingSchemaFactory recorder = runCreateSchema(null);

        assertTrue("FEATURE_SECURE_PROCESSING was not enabled",
                   Boolean.TRUE.equals(recorder.features().get(XMLConstants.FEATURE_SECURE_PROCESSING)));
        assertEquals("external DTD access was not disabled", "",
                     recorder.properties().get(XMLConstants.ACCESS_EXTERNAL_DTD));
        assertEquals("external schema access was not disabled", "",
                     recorder.properties().get(XMLConstants.ACCESS_EXTERNAL_SCHEMA));
        // Xerces - which CXF ships against - silently ignores the two properties above, so the
        // DOCTYPE itself has to be refused as well.
        assertTrue("DOCTYPE declarations are still accepted",
                   Boolean.TRUE.equals(recorder.features().get(DISALLOW_DOCTYPE_DECL_FEATURE)));
    }

    /**
     * Drives the real {@code EndpointReferenceUtils} code path with an attacker controlled schema
     * document. The control pass first proves the payload does reach out for the canary through
     * a plain, unconfigured factory.
     */
    @Test
    public void testExternalEntityIsNotResolvedWhenBuildingTheSchema() throws Exception {
        try (XXETestListener listener = new XXETestListener()) {
            String payload = maliciousSchema(listener.canaryUri());
            String systemId = listener.directoryUri() + "payload.xsd";

            // control: an unconfigured SchemaFactory happily fetches the external entity
            try {
                SchemaFactory plain = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
                plain.setErrorHandler(new IgnoringErrorHandler());
                plain.newSchema(new StreamSource(new StringReader(payload), systemId));
            } catch (SAXException ex) {
                // the payload does not have to produce a usable schema, only to be fetched
            }
            assertTrue("the payload does not reproduce the XXE, so the test proves nothing",
                       listener.canaryWasRead());
            listener.clear();

            // the shipped code path must not fetch anything
            runCreateSchema(new StreamSource(new StringReader(payload), systemId));
            assertFalse("the external entity was resolved - XXE is still possible: " + listener.reads(),
                        listener.canaryWasRead());
        }
    }

    /**
     * The companion fix wraps the resolver call in {@code AccessController.doPrivileged}; this
     * checks schema resolution still works while a SecurityManager is installed.
     */
    @Test
    public void testResourceResolverStillResolvesUnderSecurityManager() throws Exception {
        try (XXETestListener listener = new XXETestListener()) {
            Path imported = listener.write("imported.xsd",
                "<xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\""
                + " targetNamespace=\"http://xxe.test/imported\" elementFormDefault=\"qualified\">"
                + "<xs:element name=\"imported\" type=\"xs:string\"/>"
                + "</xs:schema>");

            RecordingSchemaFactory recorder = runCreateSchema(null);
            LSResourceResolver resolver = recorder.getResourceResolver();
            assertNotNull("EndpointReferenceUtils did not install a resource resolver", resolver);

            LSInput input = resolver.resolveResource(XMLConstants.W3C_XML_SCHEMA_NS_URI,
                                                     "http://xxe.test/imported", null,
                                                     listener.uriOf(imported),
                                                     listener.directoryUri());
            assertNotNull("the resolver returned nothing while a SecurityManager was installed",
                          input);
            assertNotNull(input.getByteStream());
        }
    }

    private RecordingSchemaFactory runCreateSchema(Source payload) {
        RecordingSchemaFactory.reset();
        RecordingSchemaFactory.setPayload(payload);
        System.setProperty(FACTORY_PROPERTY, RecordingSchemaFactory.class.getName());
        try {
            EndpointReferenceUtils.getSchema(new ServiceInfo());
        } finally {
            System.clearProperty(FACTORY_PROPERTY);
            RecordingSchemaFactory.setPayload(null);
        }
        RecordingSchemaFactory recorder = RecordingSchemaFactory.last();
        assertNotNull("EndpointReferenceUtils never created a SchemaFactory", recorder);
        return recorder;
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

    private static final class IgnoringErrorHandler implements ErrorHandler {
        public void warning(SAXParseException exception) {
        }

        public void error(SAXParseException exception) {
        }

        public void fatalError(SAXParseException exception) {
        }
    }

    /**
     * Stands in for the JAXP schema factory (selected through the
     * {@code javax.xml.validation.SchemaFactory:...} system property) so a test can see exactly
     * how the production code configured it, while every call still reaches a real parser.
     */
    public static final class RecordingSchemaFactory extends SchemaFactory {

        private static final List<RecordingSchemaFactory> INSTANCES = new CopyOnWriteArrayList<>();
        private static volatile Source payload;

        private final SchemaFactory delegate;
        private final Map<String, Boolean> features = new LinkedHashMap<>();
        private final Map<String, Object> properties = new LinkedHashMap<>();

        public RecordingSchemaFactory() {
            String previous = System.getProperty(FACTORY_PROPERTY);
            System.clearProperty(FACTORY_PROPERTY);
            try {
                delegate = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            } finally {
                if (previous != null) {
                    System.setProperty(FACTORY_PROPERTY, previous);
                }
            }
            INSTANCES.add(this);
        }

        static void reset() {
            INSTANCES.clear();
            payload = null;
        }

        static void setPayload(Source source) {
            payload = source;
        }

        static RecordingSchemaFactory last() {
            return INSTANCES.isEmpty() ? null : INSTANCES.get(INSTANCES.size() - 1);
        }

        Map<String, Boolean> features() {
            return features;
        }

        Map<String, Object> properties() {
            return properties;
        }

        @Override
        public boolean isSchemaLanguageSupported(String schemaLanguage) {
            return XMLConstants.W3C_XML_SCHEMA_NS_URI.equals(schemaLanguage);
        }

        @Override
        public void setErrorHandler(ErrorHandler errorHandler) {
            delegate.setErrorHandler(errorHandler);
        }

        @Override
        public ErrorHandler getErrorHandler() {
            return delegate.getErrorHandler();
        }

        @Override
        public void setResourceResolver(LSResourceResolver resourceResolver) {
            delegate.setResourceResolver(resourceResolver);
        }

        @Override
        public LSResourceResolver getResourceResolver() {
            return delegate.getResourceResolver();
        }

        @Override
        public void setFeature(String name, boolean value)
            throws SAXNotRecognizedException, SAXNotSupportedException {
            features.put(name, value);
            delegate.setFeature(name, value);
        }

        @Override
        public boolean getFeature(String name)
            throws SAXNotRecognizedException, SAXNotSupportedException {
            return delegate.getFeature(name);
        }

        @Override
        public void setProperty(String name, Object object)
            throws SAXNotRecognizedException, SAXNotSupportedException {
            properties.put(name, object);
            delegate.setProperty(name, object);
        }

        @Override
        public Object getProperty(String name)
            throws SAXNotRecognizedException, SAXNotSupportedException {
            return delegate.getProperty(name);
        }

        @Override
        public Schema newSchema(Source[] schemas) throws SAXException {
            Source[] actual = payload == null ? schemas : new Source[] {payload};
            return delegate.newSchema(actual);
        }

        @Override
        public Schema newSchema() throws SAXException {
            return delegate.newSchema();
        }
    }
}
