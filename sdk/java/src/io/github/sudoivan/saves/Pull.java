// SPDX-License-Identifier: 0BSD

package io.github.sudoivan.saves;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;

/** High level pull helper. */
public final class Pull {

    private Pull() {}

    /** Options for pull. */
    public static final class Options {
        public String app, slot, snapshotId;
        public Path dir;
        public boolean prune;
        public BiConsumer<Long, Long> onProgress;
    }

    private static void safePath(String p) {
        if (p.startsWith("/") || p.contains("\\")) throw new SavesException(400, "bad_path", "unsafe path", "", "", null, null);
        for (var seg : p.split("/"))
            if (seg.isEmpty() || seg.equals(".") || seg.equals(".."))
                throw new SavesException(400, "bad_path", "unsafe path", "", "", null, null);
    }

    /** Downloads a snapshot into a directory. */
    @SuppressWarnings("unchecked")
    public static void run(SavesClient c, Options o) throws IOException {
        var m = c.getManifest(o.app, o.slot, o.snapshotId);
        if (m.get("enc") != null) throw new SavesException(409, "encrypted", "snapshot is encrypted", "", "", null, null);
        var seen = new HashSet<Path>();
        long total = 0, done = 0;
        var files = (List<Object>) m.getOrDefault("files", List.of());
        for (var fo : files) total += Push.num(((Map<String, Object>) fo).get("size"), 0);
        for (var fo : files) {
            var f = (Map<String, Object>) fo;
            var path = (String) f.get("path");
            safePath(path);
            var dst = o.dir.resolve(path);
            Files.createDirectories(dst.getParent());
            byte[] data;
            if (f.get("inline") instanceof String) {
                data = Base64.getDecoder().decode((String) f.get("inline"));
            } else {
                var chs = (List<Object>) f.getOrDefault("chunks", List.of());
                var parts = new byte[chs.size()][];
                var pool = java.util.concurrent.Executors.newFixedThreadPool(
                    Math.min(4, Math.max(1, chs.size())));
                var futs = new ArrayList<java.util.concurrent.Future<?>>();
                for (int ci = 0; ci < chs.size(); ci++) {
                    var ch = (Map<String, Object>) chs.get(ci);
                    int idx = ci;
                    futs.add(pool.submit(() -> {
                        var b = c.getChunk(o.app, (String) ch.get("h"), 0, 0);
                        if (!Push.hex(Push.sha().digest(b)).equals(ch.get("h")))
                            throw new SavesException(0, "checksum", "chunk hash mismatch", "", "", null, null);
                        parts[idx] = b;
                    }));
                }
                try {
                    for (var fu : futs) fu.get();
                } catch (Exception e) {
                    throw new SavesException(0, "io", String.valueOf(e.getCause()), "", "", null, null);
                } finally {
                    pool.shutdown();
                }
                var n = chs.isEmpty() ? 0 : java.util.Arrays.stream(parts).mapToInt(x -> x.length).sum();
                data = new byte[n];
                var off = 0;
                for (var p : parts) { if (p != null) { System.arraycopy(p, 0, data, off, p.length); off += p.length; } }
            }
            if (data.length != Push.num(f.get("size"), -1))
                throw new SavesException(0, "size", "size mismatch", "", "", null, null);
            var tmp = dst.resolveSibling(dst.getFileName() + ".saves-tmp");
            Files.write(tmp, data);
            try {
                Files.setPosixFilePermissions(tmp, PosixFilePermissions.fromString(
                    "r" + ((Push.num(f.get("mode"), 0644) & 0400) > 0 ? "" : "-") + "---"));
            } catch (Exception ignored) { }
            Files.move(tmp, dst, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            try { Files.setLastModifiedTime(dst, java.nio.file.attribute.FileTime.from(Push.num(f.get("mtime_ns"), 0) / 1_000_000_000, java.util.concurrent.TimeUnit.SECONDS)); } catch (Exception ignored) { }
            seen.add(dst);
            done += Push.num(f.get("size"), 0);
            if (o.onProgress != null) o.onProgress.accept(done, total);
        }
        for (var d : (List<Object>) m.getOrDefault("dirs", List.of())) {
            var p = o.dir.resolve((String) d);
            Files.createDirectories(p);
            seen.add(p);
        }
        if (o.prune)
            try (var st = Files.walk(o.dir)) {
                st.filter(Files::isRegularFile).filter(p -> !seen.contains(p)).forEach(p -> {
                    try { Files.delete(p); } catch (IOException ignored) { }
                });
            }
    }
}
