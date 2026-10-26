// SPDX-License-Identifier: 0BSD

package io.github.sudoivan.saves;

import io.github.sudoivan.saves.internal.Json;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BiConsumer;

/** High level push helper. */
public final class Push {

    private Push() {}

    /** Options for push. */
    public static final class Options {
        public String app, slot, root = "save", label = "", device = "";
        public Path dir;
        public boolean force;
        public int chunkSize = 1 << 20;
        public int parallelism = 4;
        public BiConsumer<Long, Long> onProgress;
    }

    private static void safePath(String p) {
        if (p.startsWith("/") || p.contains("\\")) throw new SavesException(400, "bad_path", "unsafe path", "", "", null, null);
        for (var seg : p.split("/"))
            if (seg.isEmpty() || seg.equals(".") || seg.equals(".."))
                throw new SavesException(400, "bad_path", "unsafe path", "", "", null, null);
    }

    /** Uploads a directory as a snapshot; returns the committed head id. */
    @SuppressWarnings("unchecked")
    public static String run(SavesClient c, Options o) throws IOException, InterruptedException {
        var me = c.me();
        var lim = me.get("limits") instanceof Map ? (Map<String, Object>) me.get("limits") : Map.<String, Object>of();
        long inlineMax = num(lim.get("inline_max_bytes"), 65536);
        int cs = (int) Math.max(num(lim.get("min_chunk_bytes"), 256 << 10),
                Math.min(o.chunkSize, num(lim.get("max_chunk_bytes"), 8 << 20)));

        var files = new ArrayList<String[]>();
        var dirs = new ArrayList<String>();
        Files.walkFileTree(o.dir, new SimpleFileVisitor<>() {
            @Override public FileVisitResult preVisitDirectory(Path d, BasicFileAttributes a) {
                var rel = o.dir.relativize(d).toString().replace('\\', '/');
                if (!rel.isEmpty()) dirs.add(o.root + "/" + rel);
                return FileVisitResult.CONTINUE;
            }
            @Override public FileVisitResult visitFile(Path f, BasicFileAttributes a) throws IOException {
                if (Files.isSymbolicLink(f)) return FileVisitResult.CONTINUE;
                var rel = o.dir.relativize(f).toString().replace('\\', '/');
                safePath(rel);
                files.add(new String[] {o.root + "/" + rel, f.toString(), String.valueOf(a.size()),
                    String.valueOf(a.lastModifiedTime().toMillis() * 1_000_000)});
                return FileVisitResult.CONTINUE;
            }
        });
        files.sort(Comparator.comparing(f -> f[0]));

        var mfiles = new ArrayList<Map<String, Object>>();
        var chunks = new ArrayList<long[]>();
        var chunkMap = new ArrayList<String[]>();
        long total = 0;
        for (var f : files) {
            var path = f[0];
            var full = Path.of(f[1]);
            long size = Long.parseLong(f[2]);
            long mt = Long.parseLong(f[3]);
            total += size;
            var fe = new java.util.LinkedHashMap<String, Object>();
            fe.put("path", path);
            fe.put("size", size);
            fe.put("mode", 0644);
            fe.put("mtime_ns", mt);
            if (size <= inlineMax) {
                fe.put("inline", Base64.getEncoder().encodeToString(Files.readAllBytes(full)));
            } else {
                var data = Files.readAllBytes(full);
                var refs = new ArrayList<Map<String, Object>>();
                var md = sha();
                for (int off = 0; off < data.length; off += cs) {
                    int len = Math.min(cs, data.length - off);
                    md.reset();
                    md.update(data, off, len);
                    var h = hex(md.digest());
                    refs.add(Map.of("h", h, "n", len));
                    chunks.add(new long[] {off, len});
                    chunkMap.add(new String[] {h, f[1]});
                }
                fe.put("chunks", refs);
            }
            mfiles.add(fe);
        }

        var head = "";
        try { head = String.valueOf(c.getSlot(o.app, o.slot).get("head")); } catch (SavesException ignored) { }
        var manifest = new java.util.LinkedHashMap<String, Object>();
        manifest.put("version", 1);
        manifest.put("device", o.device);
        manifest.put("label", o.label);
        if (!head.isEmpty()) manifest.put("parent", head);
        if (!dirs.isEmpty()) manifest.put("dirs", dirs);
        manifest.put("files", mfiles);
        var bo = c.beginSnapshot(o.app, o.slot, head, manifest);
        var snapId = String.valueOf(bo.get("id"));
        var missing = new HashSet<String>();
        for (var h : (List<Object>) bo.getOrDefault("missing", List.of())) missing.add(String.valueOf(h));

        final long totalF = total;
        var done = new AtomicLong();
        var up = new ConcurrentLinkedQueue<String[]>();
        for (var h : missing) {
            for (var cm : chunkMap) if (cm[0].equals(h)) up.add(cm);
        }
        var pool2 = Executors.newFixedThreadPool(o.parallelism);
        for (int w = 0; w < o.parallelism; w++) {
            pool2.submit(() -> {
                String[] j;
                while ((j = up.poll()) != null) {
                    try {
                        var info = chunks.get(chunkMap.indexOf(j));
                        var buf = new byte[(int) info[1]];
                        try (var f = new RandomAccessFile(j[1], "r")) {
                            f.seek(info[0]);
                            f.readFully(buf);
                        }
                        c.putChunk(o.app, o.slot, snapId, j[0], buf);
                        done.addAndGet(info[1]);
                        if (o.onProgress != null) o.onProgress.accept(done.get(), totalF);
                    } catch (IOException e) {
                        throw new SavesException(0, "io", e.getMessage(), "", "", null, null);
                    }
                }
            });
        }
        pool2.shutdown();
        pool2.awaitTermination(1, TimeUnit.HOURS);
        var res = c.commitSnapshot(o.app, o.slot, snapId, head, o.force);
        return String.valueOf(res.getOrDefault("head", snapId));
    }

    static long num(Object v, long dflt) { return v instanceof Number ? ((Number) v).longValue() : dflt; }

    static java.security.MessageDigest sha() {
        try { return java.security.MessageDigest.getInstance("SHA-256"); }
        catch (java.security.NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }

    static String hex(byte[] b) {
        var sb = new StringBuilder(64);
        for (var x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
}
