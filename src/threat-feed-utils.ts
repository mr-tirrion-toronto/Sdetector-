export function parseCsv(input: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let quoted = false;

  for (let i = 0; i < input.length; i++) {
    const char = input[i];
    if (quoted) {
      if (char === '"' && input[i + 1] === '"') {
        field += '"';
        i++;
      } else if (char === '"') {
        quoted = false;
      } else {
        field += char;
      }
    } else if (char === '"') {
      quoted = true;
    } else if (char === ",") {
      row.push(field);
      field = "";
    } else if (char === "\n") {
      row.push(field.replace(/\r$/, ""));
      if (row.some(value => value.length > 0)) rows.push(row);
      row = [];
      field = "";
    } else {
      field += char;
    }
  }

  if (field.length || row.length) {
    row.push(field.replace(/\r$/, ""));
    if (row.some(value => value.length > 0)) rows.push(row);
  }
  return rows;
}

export function csvObjects(input: string): Record<string, string>[] {
  const lines = input.split(/\r?\n/);
  const headerIndex = lines.findIndex(line => {
    const trimmed = line.trimStart();
    const candidate = (trimmed.startsWith("#") ? trimmed.slice(1).trimStart() : trimmed).toLowerCase();
    return candidate.startsWith("id,dateadded,url,") || candidate.startsWith("phish_id,url,");
  });
  if (headerIndex < 0) return [];

  const headerLine = lines[headerIndex].trimStart();
  const header = headerLine.startsWith("#") ? headerLine.slice(1).trimStart() : headerLine;
  const dataLines = lines.slice(headerIndex + 1)
    .filter(line => line.trim().length > 0 && !line.trimStart().startsWith("#"));
  const rows = parseCsv([header, ...dataLines].join("\n"));
  if (!rows.length) return [];

  const headers = rows[0].map(value => value.trim().toLowerCase());
  return rows.slice(1).map(values => {
    const item: Record<string, string> = {};
    headers.forEach((name, index) => item[name] = (values[index] ?? "").trim());
    return item;
  });
}

export function canonicalUrl(raw: string): { value: string; hostname: string } | null {
  try {
    const url = new URL(raw.trim());
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    if (!url.hostname || url.hostname.length > 253) return null;
    url.username = "";
    url.password = "";
    url.hash = "";
    return { value: url.toString(), hostname: url.hostname.toLowerCase() };
  } catch {
    return null;
  }
}
