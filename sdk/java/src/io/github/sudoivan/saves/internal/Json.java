// SPDX-License-Identifier: 0BSD

package io.github.sudoivan.saves.internal;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Minimal strict JSON reader and writer. */
public final class Json {

    private Json() {}

    private static final int MAX_DEPTH = 64;

    /** Parses JSON into Map, List, String, Long, Double, Boolean or null. */
    public static Object parse(String s) {
        P p = new P(s);
        Object v = p.value(0);
        p.ws();
        if (!p.end()) throw new IllegalArgumentException("trailing data");
        return v;
    }

    private static final class P {
        final String s;
        int i;
        P(String s) { this.s = s; }
        boolean end() { return i >= s.length(); }
        char peek() { return i < s.length() ? s.charAt(i) : 0; }
        void ws() { while (peek() == ' ' || peek() == '\t' || peek() == '\n' || peek() == '\r') i++; }
        Object value(int depth) {
            if (depth > MAX_DEPTH) throw new IllegalArgumentException("too deep");
            ws();
            char c = peek();
            if (c == '{') return object(depth);
            if (c == '[') return array(depth);
            if (c == '"') return string();
            if (c == 't' && s.startsWith("true", i)) { i += 4; return Boolean.TRUE; }
            if (c == 'f' && s.startsWith("false", i)) { i += 5; return Boolean.FALSE; }
            if (c == 'n' && s.startsWith("null", i)) { i += 4; return null; }
            return number();
        }
        Map<String, Object> object(int depth) {
            var m = new LinkedHashMap<String, Object>();
            i++;
            ws();
            if (peek() == '}') { i++; return m; }
            for (;;) {
                ws();
                if (peek() != '"') throw new IllegalArgumentException("key expected");
                String k = string();
                ws();
                if (peek() != ':') throw new IllegalArgumentException("colon expected");
                i++;
                m.put(k, value(depth + 1));
                ws();
                if (peek() == '}') { i++; return m; }
                if (peek() != ',') throw new IllegalArgumentException("comma expected");
                i++;
            }
        }
        List<Object> array(int depth) {
            var l = new ArrayList<Object>();
            i++;
            ws();
            if (peek() == ']') { i++; return l; }
            for (;;) {
                l.add(value(depth + 1));
                ws();
                if (peek() == ']') { i++; return l; }
                if (peek() != ',') throw new IllegalArgumentException("comma expected");
                i++;
            }
        }
        String string() {
            i++; // "
            var sb = new StringBuilder();
            for (;;) {
                char c = s.charAt(i++);
                if (c == '"') return sb.toString();
                if (c == '\\') {
                    char e = s.charAt(i++);
                    switch (e) {
                        case '"': sb.append('"'); break;
                        case '\\': sb.append('\\'); break;
                        case '/': sb.append('/'); break;
                        case 'b': sb.append('\b'); break;
                        case 'f': sb.append('\f'); break;
                        case 'n': sb.append('\n'); break;
                        case 'r': sb.append('\r'); break;
                        case 't': sb.append('\t'); break;
                        case 'u':
                            sb.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                            i += 4;
                            break;
                        default: throw new IllegalArgumentException("bad escape");
                    }
                } else if (c < 0x20) {
                    throw new IllegalArgumentException("control char");
                } else {
                    sb.append(c);
                }
            }
        }
        Object number() {
            int st = i;
            if (peek() == '-') i++;
            while (Character.isDigit(peek())) i++;
            boolean dbl = false;
            if (peek() == '.') { dbl = true; i++; while (Character.isDigit(peek())) i++; }
            if (peek() == 'e' || peek() == 'E') {
                dbl = true; i++;
                if (peek() == '+' || peek() == '-') i++;
                while (Character.isDigit(peek())) i++;
            }
            if (st == i) throw new IllegalArgumentException("bad value");
            var n = s.substring(st, i);
            return dbl ? (Object) Double.parseDouble(n) : (Object) Long.parseLong(n);
        }
    }

    /** Serializes a value to JSON. */
    public static String write(Object v) {
        var sb = new StringBuilder();
        emit(v, sb);
        return sb.toString();
    }

    private static void emit(Object v, StringBuilder sb) {
        if (v == null) {
            sb.append("null");
        } else if (v instanceof String) {
            esc((String) v, sb);
        } else if (v instanceof Number || v instanceof Boolean) {
            sb.append(v);
        } else if (v instanceof Map) {
            sb.append('{');
            boolean first = true;
            for (var e : ((Map<?, ?>) v).entrySet()) {
                if (!first) sb.append(',');
                first = false;
                esc(String.valueOf(e.getKey()), sb);
                sb.append(':');
                emit(e.getValue(), sb);
            }
            sb.append('}');
        } else if (v instanceof Iterable) {
            sb.append('[');
            boolean first = true;
            for (var x : (Iterable<?>) v) {
                if (!first) sb.append(',');
                first = false;
                emit(x, sb);
            }
            sb.append(']');
        } else {
            throw new IllegalArgumentException("unsupported " + v.getClass());
        }
    }

    private static void esc(String s, StringBuilder sb) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        sb.append('"');
    }
}
