/** `shr_8a1f…c03e`: an id's kind, then the first and last four characters of its body. */
export function middleTruncate(id: string): string {
  const cut = id.indexOf("_");
  const kind = cut === -1 ? "" : id.slice(0, cut + 1);
  const body = cut === -1 ? id : id.slice(cut + 1);
  if (body.length <= 10) return id;
  return `${kind}${body.slice(0, 4)}…${body.slice(-4)}`;
}
