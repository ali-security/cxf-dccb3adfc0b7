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

package org.apache.cxf.io;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.cxf.Bus;
import org.apache.cxf.BusFactory;
import org.apache.cxf.bus.extension.ExtensionManagerBus;

import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import static org.awaitility.Awaitility.await;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;

@RunWith(Parameterized.class)
public class DelayedCachedOutputStreamCleanerTest {
    private final String strategy;
    private Bus bus;

    public DelayedCachedOutputStreamCleanerTest(final String strategy) {
        this.strategy = strategy;
    }

    @Parameterized.Parameters(name = CachedConstants.CLEANER_STRATEGY_BUS_PROP + "= {0}")
    public static String[] strategies() throws Exception {
        return new String[] {"default", "single-timer", null};
    }

    @After
    public void tearDown() {
        if (bus != null) {
            bus.shutdown(true);
            bus = null;
        }
    }
    
    @Test
    public void testNoop() {
        final Map<String, Object> properties = Collections.singletonMap(CachedConstants.CLEANER_DELAY_BUS_PROP, 0);
        bus = createBus(properties);
        
        final CachedOutputStreamCleaner cleaner = bus.getExtension(CachedOutputStreamCleaner.class);
        assertThat(cleaner, instanceOf(DelayedCachedOutputStreamCleaner.class)); /* noop */
        
        assertNoopCleaner(cleaner);
    }

    @Test
    public void testNoTimer() throws Exception {
        final Map<String, Object> properties =
            Collections.singletonMap(CachedConstants.CLEANER_DELAY_BUS_PROP, 2500);
        bus = createBus(properties);

        final CachedOutputStreamCleaner cleaner = bus.getExtension(CachedOutputStreamCleaner.class);
        assertThat(cleaner, instanceOf(DelayedCachedOutputStreamCleaner.class));

        // No timer (thread) should be started for the bus until the first stream is registered
        assertThat(getScheduledTimer(cleaner), nullValue());

        cleaner.register(() -> { });
        assertThat(getScheduledTimer(cleaner), notNullValue());
    }

    @Test
    public void testNoTimerAfterShutdown() throws Exception {
        final Map<String, Object> properties =
            Collections.singletonMap(CachedConstants.CLEANER_DELAY_BUS_PROP, 2500);
        bus = createBus(properties);

        final CachedOutputStreamCleaner cleaner = bus.getExtension(CachedOutputStreamCleaner.class);
        assertThat(cleaner, instanceOf(DelayedCachedOutputStreamCleaner.class));
        bus.shutdown(true);

        // The per-bus timer (thread) should not be started once the bus is shut down,
        // the single (shared) timer is never cancelled and keeps serving other buses
        cleaner.register(() -> { });
        if (!"single-timer".equals(strategy)) {
            assertThat(getScheduledTimer(cleaner), nullValue());
        }
    }

    @Test
    public void testRegisterAfterUnregister() throws InterruptedException {
        final AtomicInteger latch1 = new AtomicInteger();
        final AtomicInteger latch2 = new AtomicInteger();
        final Closeable closeable1 = () -> latch1.incrementAndGet();
        final Closeable closeable2 = () -> latch2.incrementAndGet();

        /* Delay of 2.5 seconds */
        final Map<String, Object> properties =
            Collections.singletonMap(CachedConstants.CLEANER_DELAY_BUS_PROP, 2500);
        bus = createBus(properties);

        final CachedOutputStreamCleaner cleaner = bus.getExtension(CachedOutputStreamCleaner.class);
        cleaner.register(closeable1);
        cleaner.unregister(closeable1);
        assertThat(cleaner.size(), equalTo(0));

        // The cleaner should (re)schedule the cleanup once the new stream is registered
        cleaner.register(closeable2);
        await().atMost(5, TimeUnit.SECONDS).untilAtomic(latch2, equalTo(1));
        assertThat(latch1.get(), equalTo(0));
        assertThat(cleaner.size(), equalTo(0));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInvalidStrategy() {
        final Map<String, Object> properties =
            Collections.singletonMap(CachedConstants.CLEANER_STRATEGY_BUS_PROP, "unknown");
        bus = new ExtensionManagerBus(new HashMap<>(), properties);
        new DelayedCachedOutputStreamCleaner().setBus(bus);
    }

    @Test
    public void testForceClean() throws InterruptedException {
        bus = createBus();
        
        final CachedOutputStreamCleaner cleaner = bus.getExtension(CachedOutputStreamCleaner.class);
        assertThat(cleaner, instanceOf(DelayedCachedOutputStreamCleaner.class));
        
        final AtomicBoolean latch = new AtomicBoolean(false);
        final Closeable closeable = () -> latch.compareAndSet(false, true);
        cleaner.register(closeable);
        
        final DelayedCachedOutputStreamCleaner delayedCleaner = (DelayedCachedOutputStreamCleaner) cleaner;
        delayedCleaner.forceClean();
        
        // Await for Closeable::close to be called
        assertThat(latch.get(), is(true));
    }
    
    @Test
    public void testClean() throws InterruptedException {
        final AtomicInteger latch = new AtomicInteger();
        final Closeable closeable1 = () -> latch.incrementAndGet();
        final Closeable closeable2 = () -> latch.incrementAndGet();

        /* Delay of 2.5 seconds */
        final Map<String, Object> properties = Collections.singletonMap(CachedConstants.CLEANER_DELAY_BUS_PROP, 2500);
        bus = createBus(properties);

        final CachedOutputStreamCleaner cleaner = bus.getExtension(CachedOutputStreamCleaner.class);
        cleaner.register(closeable1);
        cleaner.register(closeable2);

        // Await for Closeable::close to be called on schedule
        await().atMost(5, TimeUnit.SECONDS).untilAtomic(latch, equalTo(2));
        assertThat(cleaner, instanceOf(DelayedCachedOutputStreamCleaner.class));
    }
    
    @Test
    public void testForceCleanForEmpty() throws InterruptedException {
        bus = createBus();

        final CachedOutputStreamCleaner cleaner = bus.getExtension(CachedOutputStreamCleaner.class);
        assertThat(cleaner, instanceOf(DelayedCachedOutputStreamCleaner.class));
        
        final AtomicBoolean latch = new AtomicBoolean(false);
        final Closeable closeable = () -> latch.compareAndSet(false, true);

        cleaner.register(closeable);
        cleaner.unregister(closeable);
        
        final DelayedCachedOutputStreamCleaner delayedCleaner = (DelayedCachedOutputStreamCleaner) cleaner;
        delayedCleaner.forceClean();
        
        // Closeable::close should not be called
        assertThat(latch.get(), is(false));
    }
    
    @Test
    public void testForceCleanException() throws InterruptedException {
        bus = createBus();

        final CachedOutputStreamCleaner cleaner = bus.getExtension(CachedOutputStreamCleaner.class);
        assertThat(cleaner, instanceOf(DelayedCachedOutputStreamCleaner.class));
        
        final AtomicInteger latch = new AtomicInteger();
        final Closeable closeable2 = () -> latch.incrementAndGet();
        final Closeable closeable1 = () -> {
            latch.incrementAndGet();
            throw new IOException("Simulated");
        };
        cleaner.register(closeable1);
        cleaner.register(closeable2);

        final DelayedCachedOutputStreamCleaner delayedCleaner = (DelayedCachedOutputStreamCleaner) cleaner;
        delayedCleaner.forceClean();

        // Try to call force clean one more time
        delayedCleaner.forceClean();
        
        // Await for Closeable::close to be called
        assertThat(latch.get(), equalTo(2));
    }
    
    @Test
    public void testCleanOnShutdown() throws InterruptedException {
        /* Delay of 2.5 seconds */
        final Map<String, Object> properties = Collections.singletonMap(CachedConstants.CLEANER_DELAY_BUS_PROP, 2500);
        bus = createBus(properties);

        final AtomicBoolean latch = new AtomicBoolean();
        final Closeable closeable = () -> latch.compareAndSet(false, true);

        bus.setProperty(CachedConstants.CLEANER_DELAY_BUS_PROP, 2500); /* 2.5 seconds */
        final CachedOutputStreamCleaner cleaner = bus.getExtension(CachedOutputStreamCleaner.class);
        cleaner.register(closeable);

        // Closes the bus, the cleaner should cancel the internal timer(s)
        bus.shutdown(true);

        // The Closeable::close should be called on shutdown
        assertThat(latch.get(), is(true));
    }

    @Test
    public void testCleanOnShutdownDisabled() throws InterruptedException {
        /* Delay of 2.5 seconds */
        final Map<String, Object> properties = new HashMap<>();
        properties.put(CachedConstants.CLEANER_DELAY_BUS_PROP, 2500);
        properties.put(CachedConstants.CLEANER_CLEAN_ON_SHUTDOWN_BUS_PROP, false);
        bus = createBus(properties);

        final AtomicBoolean latch = new AtomicBoolean();
        final Closeable closeable = () -> latch.compareAndSet(false, true);

        bus.setProperty(CachedConstants.CLEANER_DELAY_BUS_PROP, 2500); /* 2.5 seconds */
        final CachedOutputStreamCleaner cleaner = bus.getExtension(CachedOutputStreamCleaner.class);
        cleaner.register(closeable);

        // Closes the bus, the cleaner should cancel the internal timer(s)
        bus.shutdown(true);

        // The Closeable::close should not be called since timer(s) is cancelled
        Thread.sleep(TimeUnit.SECONDS.toMillis(3));
        assertThat(latch.get(), is(false));
    }

    @Test
    public void testNegativeDelay() throws InterruptedException {
        final Map<String, Object> properties = Collections.singletonMap(CachedConstants.CLEANER_DELAY_BUS_PROP, -1);
        bus = createBus(properties);

        final CachedOutputStreamCleaner cleaner = bus.getExtension(CachedOutputStreamCleaner.class);
        assertThat(cleaner, instanceOf(DelayedCachedOutputStreamCleaner.class)); /* noop */

        assertNoopCleaner(cleaner);
    }

    @Test
    public void testTooSmallDelay() throws InterruptedException {
        final Map<String, Object> properties = Collections.singletonMap(CachedConstants.CLEANER_DELAY_BUS_PROP, 1500);
        bus = createBus(properties);

        final CachedOutputStreamCleaner cleaner = bus.getExtension(CachedOutputStreamCleaner.class);
        assertThat(cleaner, instanceOf(DelayedCachedOutputStreamCleaner.class)); /* noop */

        assertNoopCleaner(cleaner);
    }
    
    @Test
    public void testDelayedClean() throws InterruptedException {
        final AtomicInteger latch = new AtomicInteger();
        final Closeable closeable1 = () -> latch.incrementAndGet();
        final Closeable closeable2 = () -> latch.incrementAndGet();

        /* Delay of 5 seconds */
        final Map<String, Object> properties = Collections.singletonMap(CachedConstants.CLEANER_DELAY_BUS_PROP, 2500);
        bus = createBus(properties);

        final CachedOutputStreamCleaner cleaner = bus.getExtension(CachedOutputStreamCleaner.class);
        cleaner.register(closeable1);

        Thread.sleep(2000);
        cleaner.register(closeable2);

        // Await for Closeable::close to be called on schedule
        await().atMost(3, TimeUnit.SECONDS).untilAtomic(latch, equalTo(1));

        // Await for Closeable::close to be called on schedule
        await().atMost(5, TimeUnit.SECONDS).untilAtomic(latch, equalTo(2));

        assertThat(cleaner, instanceOf(DelayedCachedOutputStreamCleaner.class));
    }

    @Test
    public void testUnclosedCachedOutputStreamTempFileIsCleaned() throws IOException {
        final Bus oldBus = BusFactory.getThreadDefaultBus(false);
        bus = createBus();
        BusFactory.setThreadDefaultBus(bus);
        try {
            final CachedOutputStreamCleaner cleaner = bus.getExtension(CachedOutputStreamCleaner.class);
            assertThat(cleaner, instanceOf(DelayedCachedOutputStreamCleaner.class));

            // The stream goes over the threshold and is backed by the temporary file,
            // it is never closed (leaked) by the caller
            final CachedOutputStream cos = new CachedOutputStream(4);
            cos.write("Hello World!".getBytes(StandardCharsets.UTF_8));
            cos.flush();

            final File tmpFile = cos.getTempFile();
            assertThat(tmpFile, notNullValue());
            assertThat(tmpFile.exists(), is(true));
            assertThat(cleaner.size(), equalTo(1));

            ((DelayedCachedOutputStreamCleaner) cleaner).forceClean();

            // The leaked stream should be closed and the temporary file removed
            assertThat(tmpFile.exists(), is(false));
            assertThat(cleaner.size(), equalTo(0));
        } finally {
            BusFactory.setThreadDefaultBus(oldBus);
        }
    }

    @Test
    public void testUnclosedCachedOutputStreamInputStreamTempFileIsCleaned() throws IOException {
        final Bus oldBus = BusFactory.getThreadDefaultBus(false);
        bus = createBus();
        BusFactory.setThreadDefaultBus(bus);
        try {
            final CachedOutputStreamCleaner cleaner = bus.getExtension(CachedOutputStreamCleaner.class);
            assertThat(cleaner, instanceOf(DelayedCachedOutputStreamCleaner.class));

            final CachedOutputStream cos = new CachedOutputStream(4);
            cos.write("Hello World!".getBytes(StandardCharsets.UTF_8));
            cos.flush();

            final File tmpFile = cos.getTempFile();
            assertThat(tmpFile, notNullValue());

            // The input stream over the temporary file is never closed (leaked) by the caller,
            // so closing the output stream does not remove the temporary file
            final InputStream in = cos.getInputStream();
            assertThat(in, notNullValue());
            cos.close();
            assertThat(tmpFile.exists(), is(true));

            ((DelayedCachedOutputStreamCleaner) cleaner).forceClean();

            // The leaked input stream should be closed and the temporary file removed
            assertThat(tmpFile.exists(), is(false));
            assertThat(cleaner.size(), equalTo(0));
        } finally {
            BusFactory.setThreadDefaultBus(oldBus);
        }
    }

    @Test
    public void testClosedCachedOutputStreamIsUnregistered() throws IOException {
        final Bus oldBus = BusFactory.getThreadDefaultBus(false);
        bus = createBus();
        BusFactory.setThreadDefaultBus(bus);
        try {
            final CachedOutputStreamCleaner cleaner = bus.getExtension(CachedOutputStreamCleaner.class);
            assertThat(cleaner, instanceOf(DelayedCachedOutputStreamCleaner.class));

            final CachedOutputStream cos = new CachedOutputStream(4);
            cos.write("Hello World!".getBytes(StandardCharsets.UTF_8));
            cos.flush();

            final File tmpFile = cos.getTempFile();
            assertThat(tmpFile, notNullValue());
            assertThat(cleaner.size(), equalTo(1));

            final InputStream in = cos.getInputStream();
            assertThat(cleaner.size(), equalTo(2));
            in.close();
            cos.close();

            // Properly closed streams should not be tracked by the cleaner anymore
            assertThat(tmpFile.exists(), is(false));
            assertThat(cleaner.size(), equalTo(0));
        } finally {
            BusFactory.setThreadDefaultBus(oldBus);
        }
    }

    private Bus createBus() {
        return createBus(Collections.emptyMap());
    }

    private Bus createBus(Map<String, Object> properties) {
        final Map<String, Object> combined = new HashMap<>(properties);
        if (strategy != null) {
            combined.put(CachedConstants.CLEANER_STRATEGY_BUS_PROP, strategy);
        }
        return new ExtensionManagerBus(new HashMap<>(), combined);
    }

    /**
     * Returns the timer of the default cleaner, or the task the single-timer cleaner has scheduled
     * on the shared timer ({@code null} when nothing has been scheduled).
     */
    private static Object getScheduledTimer(final CachedOutputStreamCleaner cleaner) throws Exception {
        final Field cleanerField = DelayedCachedOutputStreamCleaner.class.getDeclaredField("cleaner");
        cleanerField.setAccessible(true);
        final Object delayedCleaner = cleanerField.get(cleaner);

        final String name = "SingleTimerDelayedCleaner".equals(delayedCleaner.getClass().getSimpleName())
            ? "timerTask" : "timer";
        final Field timerField = delayedCleaner.getClass().getDeclaredField(name);
        timerField.setAccessible(true);
        return timerField.get(delayedCleaner);
    }

    private void assertNoopCleaner(final CachedOutputStreamCleaner cleaner) {
        final AtomicBoolean latch = new AtomicBoolean(false);
        final Closeable closeable = () -> latch.compareAndSet(false, true);
        cleaner.register(closeable);
        
        final DelayedCachedOutputStreamCleaner delayedCleaner = (DelayedCachedOutputStreamCleaner) cleaner;
        delayedCleaner.forceClean();

        // Noop, Closeable::close should not be called
        assertThat(latch.get(), is(false));
    }
}
