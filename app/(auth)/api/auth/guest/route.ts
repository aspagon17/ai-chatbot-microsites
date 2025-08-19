import { signIn } from '@/app/(auth)/auth';
import { getUserById } from '@/lib/db/queries';
import { getToken } from 'next-auth/jwt';
import { NextResponse } from 'next/server';

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const redirectUrl = searchParams.get('redirectUrl') || '/';

  const isSecure =
    request.headers.get('x-forwarded-proto') === 'https' ||
    new URL(request.url).protocol === 'https:';

  const token = await getToken({
    req: request,
    secret: process.env.AUTH_SECRET,
    secureCookie: isSecure,
  });

  if (token) {
    // If a token exists but the DB user was wiped (e.g., dev reset),
    // re-create a fresh guest session instead of redirecting with a bad token.
    try {
      const [existing] = await getUserById(token.id);
      if (existing) {
        return NextResponse.redirect(new URL(redirectUrl, request.url));
      }
    } catch (_) {
      // fall through to signIn
    }
    return signIn('guest', { redirect: true, redirectTo: redirectUrl });
  }

  return signIn('guest', { redirect: true, redirectTo: redirectUrl });
}
