// Basic Auth para todo el sitio. Credenciales en la variable de entorno SITE_USERS
// con formato "usuario:clave,usuario2:clave2". Si falta, el sitio se bloquea.
export const config = { matcher: '/(.*)' };

function safeEqual(a, b) {
  const x = new TextEncoder().encode(a);
  const y = new TextEncoder().encode(b);
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) diff |= (x[i] || 0) ^ (y[i] || 0);
  return diff === 0;
}

function denied(status, body) {
  return new Response(body, {
    status,
    headers: {
      'WWW-Authenticate': 'Basic realm="Vizalba Ventas", charset="UTF-8"',
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Robots-Tag': 'noindex, nofollow'
    }
  });
}

export default function middleware(request) {
  const users = (process.env.SITE_USERS || '')
    .split(',')
    .map((p) => p.trim())
    .filter(Boolean)
    .map((p) => {
      const i = p.indexOf(':');
      return i < 0 ? null : [p.slice(0, i).toLowerCase(), p.slice(i + 1)];
    })
    .filter(Boolean);

  if (!users.length) return denied(503, 'Acceso no configurado.');

  const header = request.headers.get('authorization') || '';
  if (header.startsWith('Basic ')) {
    try {
      const decoded = new TextDecoder().decode(
        Uint8Array.from(atob(header.slice(6)), (c) => c.charCodeAt(0))
      );
      const i = decoded.indexOf(':');
      if (i > -1) {
        const user = decoded.slice(0, i).toLowerCase();
        const pass = decoded.slice(i + 1);
        let ok = false;
        for (const [u, p] of users) ok = (safeEqual(user, u) && safeEqual(pass, p)) || ok;
        if (ok) return new Response(null, { headers: { 'x-middleware-next': '1' } });
      }
    } catch (e) {}
  }
  return denied(401, 'Acceso restringido.');
}
