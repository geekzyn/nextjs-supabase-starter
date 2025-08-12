import { type NextRequest, NextResponse } from 'next/server'
import { updateSession } from '@/lib/supabase/middleware'

const AUTH_CONFIG = {
  PUBLIC_ROUTES: ["/login", "/auth"]
}

export async function middleware(request: NextRequest) {
  const { response, user } = await updateSession(request);
  
  if (!user && !AUTH_CONFIG.PUBLIC_ROUTES.includes(request.nextUrl.pathname)) {
    // no user and route is not public, potentially respond by redirecting the user to the login page
    const url = request.nextUrl.clone()
    url.pathname = '/login'
    return NextResponse.redirect(url)
  }

  return response
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * Feel free to modify this pattern to include more paths.
     */
    '/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)',
  ],
}
