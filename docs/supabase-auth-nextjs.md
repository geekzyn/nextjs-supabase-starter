# Supabase Auth in Next.js (App Router) 

This guide shows how to set up **Supabase Auth** in a Next.js App Router project with **server‑side rendering (SSR)**.

---

## 1 Install packages

```bash
pnpm add @supabase/supabase-js @supabase/ssr
```

---

## 2 Environment variables

Create `.env.local` in your project root and add your Supabase project URL and anon key:

```bash
NEXT_PUBLIC_SUPABASE_URL=your_supabase_project_url
NEXT_PUBLIC_SUPABASE_ANON_KEY=your_supabase_anon_key
```

---

## 3 Supabase clients

Create a folder for shared utilities (either at project root or under `src/`). The examples below assume `src` aliased as `@/`.

```
src/
└─ lib/
   └─ supabase/
      ├─ client.ts
      ├─ server.ts
      └─ middleware.ts
```

### 3.1 Client (browser)

Use the **browser client** in Client Components (code that runs in the browser). The `@supabase/ssr` helper ensures auth state is persisted in cookies (not localStorage).

```ts
// src/lib/supabase/client.ts
import { createBrowserClient } from '@supabase/ssr'

export function createClient() {
  return createBrowserClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
  )
}
```

### 3.2 Server (RSC, Server Actions, Route Handlers)

Server Components **can read** cookies but **cannot write** them unlike Server Actions and Route Handlers which can also set cookies. In Server Components, setting cookies throws. Error is being ignored/swallowed because `middleware` will perform the refresh and cookie writes on the next request anyway.

```ts
// src/lib/supabase/server.ts
import { createServerClient } from '@supabase/ssr'
import { cookies } from 'next/headers'

export async function createClient() {
  const cookieStore = await cookies()

  return createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookies: {
        getAll() {
          return cookieStore.getAll()
        },
        setAll(cookiesToSet) {
          try {
            cookiesToSet.forEach(({ name, value, options }) =>
              cookieStore.set(name, value, options)
            )
          } catch {
            // The `setAll` method was called from a Server Component.
            // This can be ignored if you have middleware refreshing
            // user sessions.
          }
        },
      },
    }
  )
}
```

### 3.3 Middleware 

Next.js middleware runs before routes are rendered/before a request is completed. Then, based on the incoming request, you can modify the response by rewriting, redirecting, modifying the request or response headers, or responding directly. It's particularly useful for implementing custom server-side logic like authentication, logging, or handling redirects. 

Create `middleware.ts` (app middleware) at the project root (or under `src/` if your Next.js config uses `srcDir`) to protect all routes from unauthorized access. Users that are not logged in will be redirected to `/login`. Configure a `matcher` to limit where it runs for performance. There’s no reason to run auth/session logic for static files and images. Create a session update `src/lib/supabase/middleware.ts` with `updateSession` function that refreshes expired tokens (via `auth.getClaims()`), and **writes** the refreshed cookies back to the response so the browser and server stay in sync. 

```ts
// src/middleware.ts
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
```

```ts
// src/lib/supabase/middleware.ts
import { createServerClient } from '@supabase/ssr'
import { NextResponse, type NextRequest } from 'next/server'

export async function updateSession(request: NextRequest) {
  let supabaseResponse = NextResponse.next({
    request,
  })

  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookies: {
        getAll() {
          return request.cookies.getAll()
        },
        setAll(cookiesToSet) {
          cookiesToSet.forEach(({ name, value }) => request.cookies.set(name, value))
          supabaseResponse = NextResponse.next({
            request,
          })
          cookiesToSet.forEach(({ name, value, options }) =>
            supabaseResponse.cookies.set(name, value, options)
          )
        },
      },
    }
  )

  // IMPORTANT: Avoid writing any logic between createServerClient and
  // supabase.auth.getClaims(). A simple mistake could make it very hard to debug
  // issues with users being randomly logged out.

  // IMPORTANT: Don't remove getClaims()
  const { data } = await supabase.auth.getClaims()

  const user = data?.claims

  // IMPORTANT: You *must* return the supabaseResponse object as it is. If you're
  // creating a new response object with NextResponse.next() make sure to:
  // 1. Pass the request in it, like so:
  //    const myNewResponse = NextResponse.next({ request })
  // 2. Copy over the cookies, like so:
  //    myNewResponse.cookies.setAll(supabaseResponse.cookies.getAll())
  // 3. Change the myNewResponse object to fit your needs, but avoid changing
  //    the cookies!
  // 4. Finally:
  //    return myNewResponse
  // If this is not done, you may be causing the browser and server to go out
  // of sync and terminate the user's session prematurely!

  return { response: supabaseResponse, user }
}
```

**Example flow: expired access token**
1. A user hits /dashboard with an expired `sb-access-token` and a valid `sb-refresh-token`.
2. Middleware runs `updateSession(request)`.
3. `getClaims()` sees the access token is expired → Supabase refreshes using the refresh token.
4. Supabase calls your `cookies.setAll([...])` with new tokens.
  - You update the request cookies (so the rest of this middleware run sees fresh tokens).
  - You rebuild NextResponse.next({ request }) and attach Set-Cookie headers for the browser.
5. You return `supabaseResponse`. Browser receives new cookies; subsequent requests are authenticated.
6. If there were no valid session at all, you’d hit the redirect to /login.

**Why this matters:** Server Components can’t write cookies, so without middleware your session could go stale until the next client navigation. The middleware proactively refreshes and writes cookies for both server and browser to use.

---
