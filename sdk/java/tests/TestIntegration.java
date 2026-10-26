// SPDX-License-Identifier: 0BSD

import io.github.sudoivan.saves.Pull;
import io.github.sudoivan.saves.Push;
import io.github.sudoivan.saves.SavesClient;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class TestIntegration {
    public static void main(String[] args) throws Exception {
        var url = System.getenv("SAVES_URL");
        var tok = System.getenv("SAVES_TOKEN");
        if (url == null || tok == null) {
            System.out.println("skipped: SAVES_URL or SAVES_TOKEN unset");
            return;
        }
        var c = SavesClient.builder().baseUrl(url).token(tok).build();
        c.me();
        var dir = Files.createTempDirectory("sdk-java-in");
        Files.createDirectories(dir.resolve("empty"));
        Files.writeString(dir.resolve("hello.txt"), "hi");
        var big = new byte[3 << 20];
        java.util.Arrays.fill(big, (byte) 7);
        Files.write(dir.resolve("big.bin"), big);
        var o = new Push.Options();
        o.app = "sdk-java"; o.slot = "saves"; o.dir = dir; o.device = "test";
        var head = Push.run(c, o);
        assert head != null && !head.isEmpty();
        var out = Files.createTempDirectory("sdk-java-out");
        var po = new Pull.Options();
        po.app = "sdk-java"; po.slot = "saves"; po.snapshotId = head; po.dir = out;
        Pull.run(c, po);
        assert Files.readString(out.resolve("save/hello.txt")).equals("hi");
        assert Files.readAllBytes(out.resolve("save/big.bin")).length == big.length;
        assert Files.isDirectory(out.resolve("save/empty"));
        var t = c.createToken("java", List.of("read"));
        c.revokeToken(String.valueOf(t.get("id")));
        System.out.println("integration passed");
    }
}
