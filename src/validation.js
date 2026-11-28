'use strict';
class HttpError extends Error {
  constructor(status, code, message, fields) { super(message); Object.assign(this, { status, code, fields }); }
}
const COMMON = ['password', 'qwerty', '123456', 'letmein', 'welcome', 'iloveyou', 'admin'];
const RESERVED = ['admin', 'root', 'support', 'system', 'security', 'loki', 'lokiauth'];
const str = v => typeof v === 'string' ? v : '';
const norm = v => str(v).normalize('NFKC').trim().toLowerCase();
const noCtl = v => !/[\u0000-\u001f\u007f<>]/.test(v);

const rules = {
  fullName(v) { v = str(v).trim().replace(/\s+/g, ' '); return v.length >= 2 && v.length <= 80 && noCtl(v) ? [v] : [v, 'Use 2–80 characters, without < or >.']; },
  username(v) { v = norm(v); if (!/^[a-z][a-z0-9_]{2,23}$/.test(v)) return [v, '3–24 characters: letters, numbers, underscore; start with a letter.'];
    return RESERVED.includes(v) || v.startsWith('demo_') ? [v, 'That username is reserved.'] : [v]; },
  email(v) { v = norm(v); return v.length <= 254 && /^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]{2,}$/.test(v) ? [v] : [v, 'Enter a valid email address.']; },
  password(v) { v = str(v);
    if (v.length < 10 || v.length > 128) return [v, 'Use 10–128 characters.'];
    if (![/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].every(r => r.test(v))) return [v, 'Add upper and lower case, a number and a symbol.'];
    return COMMON.some(c => v.toLowerCase().includes(c)) ? [v, 'Avoid common words such as "password".'] : [v]; },
  bio(v) { v = str(v).trim(); return v.length <= 240 && !/[<>]/.test(v) ? [v] : [v, 'Up to 240 characters, without < or >.']; },
  location(v) { v = str(v).trim(); return v.length <= 80 && noCtl(v) ? [v] : [v, 'Up to 80 characters.']; },
};
function validate(body, names) {
  const out = {}, errors = {};
  for (const n of names) { const [value, err] = rules[n](body[n]); out[n] = value; if (err) errors[n] = err; }
  if (Object.keys(errors).length) throw new HttpError(422, 'VALIDATION', 'Please fix the highlighted fields.', errors);
  return out;
}
module.exports = { HttpError, validate, norm, str };
