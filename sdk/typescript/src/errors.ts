// SPDX-License-Identifier: 0BSD

/** Error thrown on saves API failures. */
export class SavesError extends Error {
  status = 0;
  code = "internal";
  title = "";
  detail = "";
  requestId = "";
  retryAfter?: number;
  head?: string;
}
