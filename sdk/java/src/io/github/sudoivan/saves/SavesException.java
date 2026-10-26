// SPDX-License-Identifier: 0BSD

package io.github.sudoivan.saves;

import java.time.Duration;

/** Raised on saves API failures. */
public class SavesException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    private final int status;
    private final String code;
    private final String detail;
    private final String requestId;
    private final Duration retryAfter;
    private final String head;

    public SavesException(int status, String code, String title, String detail,
                          String requestId, Duration retryAfter, String head) {
        super(title == null || title.isEmpty() ? code : title);
        this.status = status;
        this.code = code;
        this.detail = detail;
        this.requestId = requestId;
        this.retryAfter = retryAfter;
        this.head = head;
    }

    public int status() { return status; }
    public String code() { return code; }
    public String detail() { return detail; }
    public String requestId() { return requestId; }
    public Duration retryAfter() { return retryAfter; }
    public String head() { return head; }
}
