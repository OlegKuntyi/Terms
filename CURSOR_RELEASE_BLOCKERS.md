# MedTerms — Release Blockers (CRITICAL + HIGH)

> **BASELINE COMMIT:** `0051687` (2026-04-17) — стан перед будь-якими фіксами.
> Відкотитись: `cd medterms_app && git reset --hard 0051687`
>
> Джерело: аудит 2026-04-17 (3 незалежні перевірки: Flutter code, Supabase backend, Store readiness).
> **Претензія документа "Security Audit — PASSED" у `MedTerms App Plan.md` невірна.** У subscriptions RLS є діра; RevenueCat webhook не існує взагалі. Не публікувати нічого до виправлення CRITICAL блоку.

Порядок виконання: CRITICAL (безпека) → CRITICAL (store reject) → HIGH. Не починати етап 2 поки не закритий етап 1.

---

## CRITICAL — Безпека (Supabase)

### FIX 1 — Subscriptions RLS дозволяє юзеру самому видати собі Premium

**Файл:** `supabase/schema_phase1.sql`, рядки 61–66

**Проблема:** Policy `subscriptions_write_own FOR ALL` дає authenticated користувачу INSERT/UPDATE/DELETE своїх рядків у `subscriptions`. Через PostgREST будь-хто з anon key виконує:

```sql
insert into subscriptions (user_id, status, product_id, current_period_end)
values (auth.uid(), 'active', 'premium_yearly', now() + interval '10 years');
```

→ Premium без оплати.

**Fix:** Писати в `subscriptions` має **тільки service_role** (через RevenueCat webhook, FIX 2). Видалити write policy повністю.

```sql
-- supabase/schema_phase1.sql — замінити рядки 61-66 на:

-- SELECT лишаємо, запис закриваємо для authenticated.
-- service_role обходить RLS за замовчуванням — webhook пише без policy.
drop policy if exists "subscriptions_write_own" on public.subscriptions;

-- (не створювати нову policy для INSERT/UPDATE/DELETE для authenticated)
```

Додатково в кінці файлу — `revoke` прав на запис на рівні GRANT, щоб навіть помилкова policy не дала ефекту:

```sql
revoke insert, update, delete on public.subscriptions from authenticated, anon;
grant select on public.subscriptions to authenticated;
```

**Перевірка:** з авторизованого клієнта `supabase.from('subscriptions').insert(...)` має повернути `42501 permission denied` або порожню вставку. Тестом покрити в `test/security/subscriptions_rls_test.dart`.

---

### FIX 2 — RevenueCat webhook не існує → Premium не може бути виданий легально

**Файл:** створити `supabase/functions/revenuecat-webhook/index.ts`

**Проблема:** В `MedTerms Product Overview.md` заявлено "Webhook → Supabase", але папки `functions/revenuecat-webhook/` немає. Після FIX 1 нікому записати в `subscriptions`, тобто Premium не вмикається взагалі. Навіть якщо Apple провів оплату — клієнт про це нічого не знає.

**Fix:** Створити Edge Function, яка:
1. Перевіряє Authorization header (shared secret, налаштований в RevenueCat Dashboard → Project Settings → Webhooks → Authorization Header).
2. Парсить `INITIAL_PURCHASE`, `RENEWAL`, `CANCELLATION`, `EXPIRATION`, `UNCANCELLATION`, `PRODUCT_CHANGE`, `BILLING_ISSUE`, `NON_RENEWING_PURCHASE`.
3. Пише в `subscriptions` через service_role (upsert за `user_id`).
4. Маппить `app_user_id` → `auth.users.id` (RevenueCat має бути налаштований так, щоб `app_user_id = supabase user id`).

```typescript
// supabase/functions/revenuecat-webhook/index.ts
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.45.0";

const RC_WEBHOOK_SECRET = Deno.env.get("REVENUECAT_WEBHOOK_SECRET")!;
const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_ROLE = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

const admin = createClient(SUPABASE_URL, SERVICE_ROLE, {
  auth: { persistSession: false, autoRefreshToken: false },
});

type RCEvent = {
  type: string;
  app_user_id: string;
  product_id?: string;
  expiration_at_ms?: number;
  period_type?: string;
  environment?: "SANDBOX" | "PRODUCTION";
};

serve(async (req) => {
  if (req.method !== "POST") {
    return new Response("Method not allowed", { status: 405 });
  }

  // 1. Auth
  const auth = req.headers.get("authorization") ?? "";
  if (auth !== `Bearer ${RC_WEBHOOK_SECRET}`) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  // 2. Parse
  let body: { event: RCEvent };
  try {
    body = await req.json();
  } catch {
    return new Response("bad json", { status: 400 });
  }
  const ev = body.event;
  if (!ev?.app_user_id || !ev?.type) {
    return new Response("missing fields", { status: 400 });
  }

  // 3. Decide status
  const activeTypes = new Set([
    "INITIAL_PURCHASE",
    "RENEWAL",
    "UNCANCELLATION",
    "PRODUCT_CHANGE",
    "NON_RENEWING_PURCHASE",
  ]);
  const inactiveTypes = new Set([
    "CANCELLATION",
    "EXPIRATION",
    "BILLING_ISSUE",
  ]);

  let status: "active" | "inactive" | "in_grace";
  if (activeTypes.has(ev.type)) status = "active";
  else if (inactiveTypes.has(ev.type)) status = "inactive";
  else {
    // TEST, TRANSFER, SUBSCRIBER_ALIAS — ignore or log
    return new Response(JSON.stringify({ ignored: ev.type }), { status: 200 });
  }

  // 4. Upsert
  const { error } = await admin
    .from("subscriptions")
    .upsert(
      {
        user_id: ev.app_user_id,
        provider: "revenuecat",
        status,
        product_id: ev.product_id ?? null,
        current_period_end: ev.expiration_at_ms
          ? new Date(ev.expiration_at_ms).toISOString()
          : null,
        updated_at: new Date().toISOString(),
      },
      { onConflict: "user_id,provider" }
    );

  if (error) {
    console.error("[rc-webhook] upsert failed:", error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }

  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
});
```

Додати в `supabase/config.toml`:

```toml
[functions.revenuecat-webhook]
verify_jwt = false
```

(`verify_jwt = false` бо RevenueCat не надсилає Supabase JWT — ми авторизуємо по shared secret власноруч.)

Deploy:

```bash
supabase functions deploy revenuecat-webhook
supabase secrets set REVENUECAT_WEBHOOK_SECRET=<згенерувати --openssl rand -hex 32>
```

У RevenueCat Dashboard → Project → Integrations → Webhooks → URL: `https://<project>.supabase.co/functions/v1/revenuecat-webhook`, Authorization header: `Bearer <той самий секрет>`.

**Клієнт Flutter:** переконатись що при логіні викликається `Purchases.logIn(userId)` де `userId == supabase.auth.currentUser.id`. Перевірити в `lib/src/features/payment/revenue_cat_premium.dart` — якщо там `anonymousId` або нічого, додати виклик на подію `onAuthStateChange`.

---

### FIX 3 — Email Edge Functions — відкритий phishing-relay

**Файли:** 
- `supabase/config.toml` (рядки з `verify_jwt = false` для send-*)
- `supabase/functions/send-confirm-email/index.ts`
- `supabase/functions/send-password-reset-email/index.ts`
- `supabase/functions/send-welcome-email/index.ts`
- `supabase/functions/send-security-notification/index.ts`

**Проблема:** Всі `send-*-email` функції мають `verify_jwt = false` і не перевіряють внутрішній секрет. Будь-хто з URL проекту робить `POST /functions/v1/send-welcome-email {"email":"victim@gmail.com", "resetLink":"https://evil.com"}` → жертва отримує лист від твого домену з фішинговим посиланням. Репутаційний удар + блок SMTP-провайдера.

**Fix:** Всі `send-*` функції мають викликатись **тільки з `auth-hook-send-email`** (server-to-server) через internal shared secret.

Крок 1 — додати перевірку internal secret у кожну `send-*` функцію:

```typescript
// На початку serve(async (req) => { ... })
const INTERNAL_SECRET = Deno.env.get("INTERNAL_EMAIL_SECRET")!;
const provided = req.headers.get("x-internal-secret") ?? "";
if (provided !== INTERNAL_SECRET) {
  return new Response(JSON.stringify({ error: "forbidden" }), {
    status: 403,
    headers: { "Content-Type": "application/json" },
  });
}
```

Крок 2 — у `auth-hook-send-email/index.ts` при виклику інших функцій додавати header:

```typescript
// приклад виклику send-confirm-email з auth-hook
await fetch(`${Deno.env.get("SUPABASE_URL")}/functions/v1/send-confirm-email`, {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "x-internal-secret": Deno.env.get("INTERNAL_EMAIL_SECRET")!,
  },
  body: JSON.stringify({ email, confirmLink, language }),
});
```

Крок 3 — deploy секрет:

```bash
supabase secrets set INTERNAL_EMAIL_SECRET=$(openssl rand -hex 32)
```

**Перевірка:** `curl -X POST https://<project>.supabase.co/functions/v1/send-welcome-email -d '{"email":"test@test.com"}'` → 403 forbidden.

---

### FIX 4 — auth-hook підпис обходиться якщо заголовок/секрет відсутні

**Файл:** `supabase/functions/auth-hook-send-email/index.ts`, рядок 36

**Проблема:**

```typescript
if (signature && AUTH_HOOK_SECRET) {
  if (!verifySignature(...)) return 401;
}
// Якщо signature відсутнє АБО AUTH_HOOK_SECRET пустий — проходить без перевірки.
```

Атакуючий просто не додає header → верифікація пропускається.

**Fix:** Вимагати обидва. Якщо хоч одне відсутнє — 401.

```typescript
// Замінити рядки 34-43:
const signature = req.headers.get("x-supabase-signature");

if (!AUTH_HOOK_SECRET) {
  console.error("[auth-hook] AUTH_HOOK_SECRET not configured");
  return new Response(JSON.stringify({ error: "server misconfigured" }), {
    status: 500,
    headers: { "Content-Type": "application/json" },
  });
}

if (!signature || !verifySignature(rawBody, signature, AUTH_HOOK_SECRET)) {
  return new Response(JSON.stringify({ error: "Invalid signature" }), {
    status: 401,
    headers: { "Content-Type": "application/json" },
  });
}
```

---

### FIX 5 — handle_new_user trigger відсутній

**Файл:** додати в кінець `supabase/schema_phase1.sql` (або новий файл `supabase/handle_new_user.sql`)

**Проблема:** `profiles` row створюється клієнтом після `signUp`. Якщо мережа впала між auth і insert → юзер існує в `auth.users` без профілю, апка падає в нулі на `profile_page.dart`.

**Fix:** автоматичний trigger.

```sql
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, email, first_name, last_name)
  values (
    new.id,
    coalesce(new.email, ''),
    coalesce(new.raw_user_meta_data->>'first_name', ''),
    coalesce(new.raw_user_meta_data->>'last_name', '')
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();
```

**Перевірка:** видалити тестового юзера, зареєструватись через апку з вимкненою мережею після `signUp` — після перезапуску профіль має існувати.

---

### FIX 6 — REVENUECAT_PUBLIC_KEY порожній в env.json

**Файл:** `env.json`, ключ `REVENUECAT_PUBLIC_KEY`

**Проблема:** у `main.dart:60` є guard `if (AppConfig.revenueCatPublicKey.isNotEmpty) { Purchases.configure(...) }`. Ключ порожній → RC не ініціалізується → paywall показує UI, кнопка Buy нічого не робить.

**Fix:**
1. RevenueCat Dashboard → Project → API keys → скопіювати **Public SDK Key** (iOS) та **Public SDK Key** (Android).
2. Внести в `env.json` окремо для платформ (додати два поля):

```json
{
  "REVENUECAT_PUBLIC_KEY_IOS": "appl_...",
  "REVENUECAT_PUBLIC_KEY_ANDROID": "goog_..."
}
```

3. У `lib/src/core/config/app_config.dart` додати платформозалежний геттер:

```dart
import 'dart:io' show Platform;
import 'package:flutter/foundation.dart' show kIsWeb;

static String get revenueCatPublicKey {
  if (kIsWeb) return '';
  if (Platform.isIOS) return _iosKey;
  if (Platform.isAndroid) return _androidKey;
  return '';
}

static const _iosKey = String.fromEnvironment('REVENUECAT_PUBLIC_KEY_IOS');
static const _androidKey = String.fromEnvironment('REVENUECAT_PUBLIC_KEY_ANDROID');
```

4. Build: `flutter build ios --dart-define-from-file=env.json --release`

---

### FIX 7 — DELETE policy на storage.avatars відсутня

**Файл:** `supabase/schema_phase1.sql` (кінець файлу)

**Проблема:** юзер не може сам видалити свій аватар через клієнта (немає policy). `delete-user` Edge Function видаляє через service_role — це ок для видалення акаунту, але якщо юзер просто змінює аватар — старий файл залишається orphaned.

**Fix:**

```sql
create policy "avatars_delete_own"
  on storage.objects
  for delete
  to authenticated
  using (
    bucket_id = 'avatars'
    and auth.uid()::text = (storage.foldername(name))[1]
  );
```

---

### FIX 8 — .vscode/launch.json тримає SUPABASE_ANON_KEY

**Файл:** `.gitignore`, `.vscode/launch.json`

**Проблема:** `.vscode/launch.json` трекається git і містить SUPABASE_ANON_KEY хардкодом. Anon key публічний за дизайном — але це сигнал низької гігієни, інші секрети можуть туди протекти.

**Fix:**

```bash
# Додати в .gitignore:
.vscode/launch.json

# Вилучити з трекінгу:
git rm --cached .vscode/launch.json
```

Приклад `launch.example.json` лишити (без ключів, з плейсхолдерами), закомітити.

---

## CRITICAL — Store submission blockers

### FIX 9 — iOS Info.plist бракує обов'язкових usage descriptions

**Файл:** `ios/Runner/Info.plist`

**Проблема:** Apple реджектить апку з image_picker / AdMob IDFA / мікрофон без відповідних `Usage Description` рядків.

**Fix:** Додати перед `</dict>` (приблизно рядок 79):

```xml
<key>NSPhotoLibraryUsageDescription</key>
<string>MedTerms needs access to your photos so you can set a profile avatar.</string>
<key>NSCameraUsageDescription</key>
<string>MedTerms needs camera access so you can take a profile photo.</string>
<key>NSUserTrackingUsageDescription</key>
<string>We use your identifier to show relevant ads and keep the free version available. You can decline without losing functionality.</string>
<key>ITSAppUsesNonExemptEncryption</key>
<false/>
```

Локалізувати (DE, UK, RU, AR, TR, PL — мови твоєї апки): створити `ios/Runner/*.lproj/InfoPlist.strings` для кожної мови з перекладами цих полів. Apple тепер приймає локалізовані prompt'и.

**Додатково — SKAdNetwork:** в `Info.plist` зараз 1 SKAN identifier. Google публікує список ~80 SKAN ID для AdMob — скопіювати повний список з https://developers.google.com/admob/ios/ios14 у блок `<key>SKAdNetworkItems</key>`. Без них атрибуція реклами зламана.

---

### FIX 10 — Sign in with Apple не підключений (Guideline 4.8)

**Файли:** 
- `ios/Runner/Runner.entitlements` (створити)
- `ios/Runner.xcodeproj/project.pbxproj` (додати capability)
- `lib/src/features/auth/...` (додати кнопку)

**Проблема:** Апка пропонує Google OAuth (через `signInWithOAuth`). Apple Guideline 4.8 з 2020: якщо є third-party login (Google/Facebook) — **обов'язково** має бути Sign in with Apple, інакше reject.

**Fix:**

1. Створити `ios/Runner/Runner.entitlements`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.developer.applesignin</key>
    <array>
        <string>Default</string>
    </array>
</dict>
</plist>
```

2. У Xcode → Runner target → Signing & Capabilities → + Capability → **Sign in with Apple** (це додасть посилання на `.entitlements` у pbxproj автоматично).

3. У Apple Developer Console: App ID → Capabilities → увімкнути Sign in with Apple → регенерувати provisioning profile.

4. У Supabase Dashboard → Authentication → Providers → Apple → налаштувати (Service ID, Team ID, Key ID, private key `.p8`). Інструкція: https://supabase.com/docs/guides/auth/social-login/auth-apple

5. Додати кнопку в `lib/src/features/auth/auth_pages.dart` (там, де вже є Google):

```dart
import 'package:flutter/foundation.dart' show kIsWeb, defaultTargetPlatform;
import 'package:flutter/services.dart';

// Показувати тільки на iOS + macOS:
if (!kIsWeb && defaultTargetPlatform == TargetPlatform.iOS)
  SignInWithAppleButton(onPressed: _onAppleSignIn),

Future<void> _onAppleSignIn() async {
  final rawNonce = Supabase.instance.client.auth.generateRawNonce();
  final hashedNonce = sha256.convert(utf8.encode(rawNonce)).toString();

  final credential = await SignInWithApple.getAppleIDCredential(
    scopes: [AppleIDAuthorizationScopes.email, AppleIDAuthorizationScopes.fullName],
    nonce: hashedNonce,
  );

  final idToken = credential.identityToken;
  if (idToken == null) throw 'No identity token';

  await Supabase.instance.client.auth.signInWithIdToken(
    provider: OAuthProvider.apple,
    idToken: idToken,
    nonce: rawNonce,
  );
}
```

Пакет: `sign_in_with_apple: ^6.1.0` у `pubspec.yaml`.

---

### FIX 11 — Android release signing = debug keystore

**Файли:**
- `android/key.properties` (створити, gitignored)
- `android/app/build.gradle` (рядки 55-61)

**Проблема:** Release build підписаний debug keystore → Google Play відмовляє завантажити .aab. Play потребує upload keystore.

**Fix:**

1. Згенерувати upload keystore (зберегти в безпечному місці, бекап обов'язковий — втрата = втрата можливості оновлювати апку):

```bash
keytool -genkey -v -keystore ~/medterms-upload.jks \
  -keyalg RSA -keysize 2048 -validity 10000 \
  -alias medterms-upload
```

2. Створити `android/key.properties` (НЕ комітити):

```properties
storePassword=<password>
keyPassword=<password>
keyAlias=medterms-upload
storeFile=/Users/olegkuntyi/medterms-upload.jks
```

3. Додати в `.gitignore`:

```
android/key.properties
```

4. Оновити `android/app/build.gradle` (замінити рядки 55-62):

```gradle
    // Перед android { ... }:
    def keystoreProperties = new Properties()
    def keystorePropertiesFile = rootProject.file('key.properties')
    if (keystorePropertiesFile.exists()) {
        keystorePropertiesFile.withReader('UTF-8') { reader ->
            keystoreProperties.load(reader)
        }
    }

    // Всередині android { } додати перед buildTypes:
    signingConfigs {
        release {
            keyAlias keystoreProperties['keyAlias']
            keyPassword keystoreProperties['keyPassword']
            storeFile keystoreProperties['storeFile'] ? file(keystoreProperties['storeFile']) : null
            storePassword keystoreProperties['storePassword']
        }
    }

    buildTypes {
        release {
            signingConfig signingConfigs.release
            minifyEnabled true
            shrinkResources true
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
        }
    }
```

5. Створити `android/app/proguard-rules.pro` з правилами для Supabase, RevenueCat, AdMob (інакше release буде падати):

```
# Flutter
-keep class io.flutter.** { *; }
-keep class io.flutter.plugins.** { *; }

# Supabase / gotrue / ktor (через JNI)
-keep class com.supabase.** { *; }

# RevenueCat
-keep class com.revenuecat.purchases.** { *; }

# AdMob / Play Services
-keep class com.google.android.gms.** { *; }
-keep class com.google.ads.** { *; }

# Sentry
-keep class io.sentry.** { *; }
-dontwarn io.sentry.**

# Keep model classes (adjust package!)
-keep class education.germanmove.medterms.** { *; }
```

**Перевірка:** `flutter build appbundle --release` має зібратись без warnings. Перевірити що APK підписаний upload key: `jarsigner -verify -verbose build/app/outputs/bundle/release/app-release.aab`.

---

### FIX 12 — AndroidManifest.xml бракує permissions

**Файл:** `android/app/src/main/AndroidManifest.xml`

**Проблема:** release білди не успадковують INTERNET permission з debug manifest → мережа не працює. BILLING permission для IAP теж має бути явним. ACCESS_NETWORK_STATE для RevenueCat offline-handling.

**Fix:** Перед `<application>` (після рядка 2):

```xml
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>
    <uses-permission android:name="com.android.vending.BILLING"/>
    <!-- AdMob -->
    <uses-permission android:name="com.google.android.gms.permission.AD_ID"/>
```

Note: `AD_ID` — Google тепер окремо трекає це в Data Safety формі.

---

### FIX 13 — targetSdk має бути ≥ 34 (Google вимога)

**Файли:** `android/app/build.gradle` рядок 50, `android/gradle.properties`

**Проблема:** `targetSdkVersion flutter.targetSdkVersion` — залежить від версії Flutter SDK. Старші Flutter 3.16- вертають 33 → Google Play блокує upload.

**Fix:** Зафіксувати явно:

```gradle
defaultConfig {
    applicationId "education.germanmove.medterms"
    minSdkVersion 21  // рекомендовано, 19 вже EOL для новіших плагінів
    targetSdkVersion 34
    compileSdkVersion 34
    versionCode flutterVersionCode.toInteger()
    versionName flutterVersionName
    multiDexEnabled true
}
```

Також `compileSdkVersion 34` замість `flutter.compileSdkVersion` (рядок 29).

**Перевірка:** `./gradlew app:dependencies | grep -i target`

---

### FIX 14 — In-app delete account UI відсутній (Apple 5.1.1(v) + GDPR)

**Файли:** `lib/src/features/settings/...` або `lib/src/features/profile/profile_page.dart`

**Проблема:** Apple з 2022 вимагає видалення акаунту безпосередньо з апки (не через email-запит, не через веб). GDPR Art. 17 — теж. Edge Function `delete-user` у тебе існує, треба підключити UI.

**Fix:** Додати кнопку "Delete my account" внизу ProfilePage або SettingsPage з двоступеневим підтвердженням:

```dart
Future<void> _onDeleteAccount(BuildContext context, WidgetRef ref) async {
  // Step 1: warning dialog
  final confirm1 = await showDialog<bool>(
    context: context,
    builder: (_) => AlertDialog(
      title: Text(l10n.deleteAccountTitle),
      content: Text(l10n.deleteAccountWarning),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context, false), child: Text(l10n.cancel)),
        TextButton(onPressed: () => Navigator.pop(context, true), child: Text(l10n.continueButton, style: const TextStyle(color: Colors.red))),
      ],
    ),
  );
  if (confirm1 != true) return;

  // Step 2: re-auth (password prompt)
  final password = await _promptPassword(context);
  if (password == null) return;

  try {
    // Re-authenticate
    final email = Supabase.instance.client.auth.currentUser!.email!;
    await Supabase.instance.client.auth.signInWithPassword(email: email, password: password);

    // Call delete-user Edge Function
    final res = await Supabase.instance.client.functions.invoke('delete-user');
    if (res.status != 200) throw 'Failed: ${res.data}';

    await Supabase.instance.client.auth.signOut();
    if (context.mounted) context.go('/login');
  } catch (e) {
    if (context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Error: $e')));
    }
  }
}
```

Перекласти strings на всі 11 мов у `lib/l10n/`.

**Перевірка:** пройти весь потік на тестовому юзері. Через 30 днів Apple може запросити відео процесу — записати один раз і зберегти.

---

### FIX 15 — Store screenshots і метадані відсутні

**Папка:** `medterms_app/marketing/`

**Проблема:** зараз тільки іконки. Неможливо подати ні в App Store Connect, ні в Play Console без скріншотів.

**Fix (мінімум для ship):**

1. **iOS скріншоти (обов'язкові розміри):**
   - iPhone 6.9" (iPhone 15 Pro Max): 1290 × 2796 — **обов'язково**
   - iPhone 6.5" (iPhone 11 Pro Max / 14 Plus): 1284 × 2778 або 1242 × 2688 — **обов'язково**
   - iPad 13" (M4 iPad Pro): 2064 × 2752 — **обов'язково якщо апка підтримує iPad** (зараз у тебе `LSRequiresIPhoneOS=true` тобто iPad disabled — перевір чи це свідоме рішення)
   - Мінімум 3 скріна на розмір, максимум 10.

2. **Android скріншоти:**
   - Phone: 1080 × 1920+ (мінімум 2, максимум 8)
   - 7" tablet, 10" tablet — опціонально але бажано
   - **Feature graphic: 1024 × 500** — обов'язково для Google Play

3. **Генерація:** використати `flutter_screenshot_tests` або вручну через симулятор (Cmd+S в iOS Simulator, Power+Vol на Android emulator). Рекомендую:

```bash
# Встановити screenshots tool
dart pub global activate screenshots

# Заповнити screenshots.yaml
# Запустити:
screenshots
```

4. **Метадані iOS** (App Store Connect):
   - Назва (30 chars): `MedTerms: FSP Medizin-Deutsch`
   - Subtitle (30 chars): `Fachsprache für Ärzte lernen`
   - Keywords (100 chars, з `MedTerms ASO Strategy.md`): `Fachsprachprüfung,FSP,Approbation,medizinisch,Fachbegriffe,Arzt,Deutsch,Kenntnisprüfung,Terminologie`
   - Opis (4000 chars): написати окремим текстом, взяти з aso_report_v2.md

5. **Метадані Android** (Google Play):
   - Назва (50): `MedTerms — Fachsprachprüfung & Approbation`
   - Short description (80): `2934 medizinische Fachbegriffe Lat-De-Pat. Mit Audio & Spaced Repetition.`
   - Full description (4000): з ASO.

6. **Privacy policy + Terms URL:** `privacy.html`, `terms.html` зараз лежать в `/Desktop/Terms/`. Треба захостити на публічному URL. Опції:
   - GitHub Pages (у тебе вже є `medterms-pages` папка) → `https://<username>.github.io/medterms-pages/privacy.html`
   - Кастомний домен
   Перевірити що URL відкривається публічно перед submit.

---

## HIGH — продуктові ризики (не блокують reject, але ранять після релізу)

### FIX 16 — Рішення по FSRS / Spaced Repetition

**Файл:** `lib/src/features/games/shared/term_status_model.dart` + маркетингові тексти

**Проблема:** Документи і маркетинг кажуть "Spaced Repetition". Реалізація — `{status: unlearned/learned/paused, correctCount}` = лічильник, не SRS. На reddit за цим ловлять.

**Варіанти:**

**A (швидкий):** Викинути "Spaced Repetition" з усіх текстів (App Plan, ASO Strategy, Store listing). Замінити на "Structured flashcards" або "Learning queue". Чесний маркетинг ≠ reject.

**B (правильний):** Додати FSRS-lite. Пакет `fsrs_dart: ^0.5.0` або реалізувати вручну (FSRS-4 — ~100 LOC). Модель `term_status` розширити:

```dart
class TermStatus {
  final String termId;
  final double stability;
  final double difficulty;
  final DateTime? nextReview;
  final int reps;
  final int lapses;
  final DateTime lastReview;
}
```

Міграція БД:

```sql
alter table term_statuses
  add column stability double precision default 0,
  add column difficulty double precision default 0,
  add column next_review timestamptz,
  add column reps integer default 0,
  add column lapses integer default 0,
  add column last_review timestamptz;
```

**Рекомендація:** для v1.0 — варіант A. Для v1.1 — B.

---

### FIX 17 — Audio offline fallback UX

**Файли:** `lib/src/core/config/audio_config.dart`, `lib/src/features/audio/audio_cache_page.dart`

**Проблема:** 17k mp3 стрімляться з R2 Cloudflare через `just_audio_cache`. Без інтернету апка мертва → "doesn't work offline" 1-star reviews.

**Fix:**

1. У `audio_cache_page.dart` (він існує — перевір що робить) — додати кнопки:
   - "Download all audio (~850MB)"
   - "Download by Fachgebiet" (для кожної з 19 спеціальностей)
   - Прогрес-бар + "Cancel"
   - Розмір кешу + кнопка Clear

2. Технічно: `just_audio_cache` має `preload()` API. Список mp3 URL → batch download через `dio` з progress callback.

3. В Settings → Storage показувати "Audio cached: X/17604 (Y MB)".

4. У Store description явно вказати: "Audio streams from cloud (~3KB per term). For offline use, download packs in Settings → Storage".

---

### FIX 18 — Payment flow немає тестів

**Файли:** `test/features/payment/...` (створити)

**Проблема:** 11 unit-тестів, але **жоден** не покриває purchase / restore / entitlement logic. Якщо RC SDK апдейт зламає `getCustomerInfo()` — побачиш на продакшені через negative reviews.

**Fix:** додати мінімум:

```dart
// test/features/payment/subscription_controller_test.dart
import 'package:flutter_test/flutter_test.dart';
import 'package:mocktail/mocktail.dart';
// ...

class MockPurchases extends Mock implements Purchases {}

void main() {
  group('SubscriptionController', () {
    test('user without entitlement → not premium', () async {
      final mock = MockPurchases();
      when(() => mock.getCustomerInfo()).thenAnswer((_) async => /* stub with empty entitlements */);
      // ...
      expect(controller.isPremium, false);
    });

    test('user with active premium_yearly → isPremium=true', () async { ... });
    test('expired entitlement → isPremium=false', () async { ... });
    test('restorePurchases propagates error to UI', () async { ... });
  });
}
```

Мінімум 4 тести — один день роботи.

---

### FIX 19 — UMP SDK consent для EU (AdMob / GDPR)

**Файл:** `lib/src/core/services/consent_service.dart`

**Проблема:** Файл існує — але треба перевірити що він реально **викликається до ініціалізації AdMob** і показує UMP dialog в EU. Без цього AdMob показує non-personalized ads (втрата revenue) + ризик Play violation notice.

**Fix (перевірити й виправити):**

1. В `main.dart` послідовність має бути:

```dart
await _consentService.initialize(); // UMP dialog if EU
if (_consentService.canRequestAds) {
  await MobileAds.instance.initialize();
}
```

2. Пакет: `google_mobile_ads` має вбудований UMP wrapper — використати `ConsentInformation.instance.requestConsentInfoUpdate()`.

3. Debug: `ConsentDebugSettings(testIdentifiers: ['YOUR_DEVICE_ID'], geography: DebugGeography.debugGeographyEea)` — симулювати EU під час розробки.

---

### FIX 20 — Refactor God-pages (opt-in, post-launch)

**Файли:**
- `lib/src/features/auth/auth_pages.dart` (892 LOC)
- `lib/src/features/home/home_page.dart` (804)
- `lib/src/features/profile/profile_page.dart` (790)
- `lib/src/features/games/audio_choice/audio_choice_page.dart` (800)
- `lib/src/features/games/learned/learned_terms_page.dart` (828)

**Проблема:** 500+ LOC у Widget-файлі = мікс UI + контролер + сервісна логіка. Кожен баг після релізу — години пошуку.

**Fix (post-launch, не блокує ship):** винести контролер/business-logic у Riverpod `Notifier` / `AsyncNotifier` з окремого файлу. UI файл тільки з `build()` методом.

---

## HIGH — додаткові знахідки з code review (2026-04-17)

### FIX 21 — Core → Features layer violations

**Файли (попередньо):**
- `lib/src/core/config/feature_gate.dart` — імпортує з `lib/src/features/`
- `lib/src/core/providers/global_settings_provider.dart` — посилання на `auth_controller.dart` з features

**Проблема:** `core/` повинен бути нижнім шаром, від якого залежать `features/`. Інвертовані імпорти створюють циклічні залежності, блокують винесення модулів у packages, провокують повторні ініціалізації при hot reload.

**Fix:**

1. Провести повний `grep -R "features" lib/src/core/` і виписати кожен імпорт.
2. Для кожного — рішення:
   - Якщо у `core/` потрібні тільки типи / інтерфейси — винести їх у `lib/src/core/types/` або `lib/src/core/contracts/`, і `features/` хай імпортує звідти.
   - Якщо core реально потребує логіки з features — це архітектурна помилка, перемістити файл у відповідний feature або у `lib/src/shared/`.
3. Додати lint-правило в `analysis_options.yaml`:

```yaml
analyzer:
  plugins:
    - custom_lint

custom_lint:
  rules:
    - avoid_core_to_features_imports
```

Або простіше: `dart_code_metrics` з правилом `no-boolean-literal-compare` + CI check `grep -R "features" lib/src/core/ && exit 1`.

**Acceptance:** `grep -R "package:.*/features/" lib/src/core/` повертає 0 рядків.

---

### FIX 22 — Router не ребілдиться при зміні subscriptionControllerProvider

**Файл:** `lib/src/core/navigation/router.dart`

**Проблема:** `GoRouter` створюється один раз з `refreshListenable`, яке слухає лише `currentUserProvider` (або аналог). Після купівлі Premium `subscriptionControllerProvider.state` міняється, але router не дізнається — залишаються активні guards типу "це premium-only, редірект на paywall". Юзер платить, натискає "закрити paywall" і знову бачить paywall.

**Fix:**

```dart
final routerProvider = Provider<GoRouter>((ref) {
  final router = GoRouter(
    refreshListenable: GoRouterRefreshStream([
      // existing: auth state
      Supabase.instance.client.auth.onAuthStateChange,
      // NEW: subscription state
      ref.watch(subscriptionControllerProvider.notifier).stream,
    ]),
    redirect: (context, state) {
      final isPremium = ref.read(subscriptionControllerProvider).isPremium;
      // ... existing logic
    },
    routes: [...],
  );
  ref.onDispose(router.dispose);
  return router;
});
```

Або простіше через `ValueNotifier`-адаптер, якщо `SubscriptionController` не стрімить.

**Acceptance:** 
1. Юзер відкриває `/paywall` на free tier.
2. Натискає Buy → MockPurchases повертає active entitlement → `subscriptionControllerProvider` оновлюється.
3. Router автоматично робить redirect з `/paywall` на `/home` (або залишається, але без guard).
4. **Без hot reload.**

Test: `test/features/payment/paywall_auto_dismiss_test.dart`.

---

### FIX 23 — Paywall guard bypass сценарії

**Файл:** `lib/src/core/navigation/router.dart`

**Проблема:** треба розслідувати три сценарії перед release:

1. **Deeplink на premium route без login:** Якщо юзер переходить `medterms://premium-stats` з Safari, а apка не авторизована — чи редіректить правильно на `/login` → після логіну повертає до `/premium-stats` → показує paywall? Чи зависає? Чи крашить?

2. **System back з premium-only екрану на публічний:** Premium user → скасував підписку → `subscriptionControllerProvider` = free → юзер натискає Android back button з `/leaderboard` (assuming it's premium). GoRouter redirect має спрацювати на кожному transition — перевірити.

3. **Restored session race:** `main.dart` спочатку читає cached session → router стартує з авторизованим станом → потім RevenueCat перевіряє entitlement (asynchronous) → заходить на premium без перевірки. Guard має чекати повного ініціалізованого `SubscriptionController`.

**Fix:** розписати кожен сценарій окремим redirect-правилом в `router.dart` + e2e test на кожен.

**Acceptance:** 
- `test/features/navigation/paywall_bypass_test.dart` покриває всі три.
- Manual test на реальному iOS/Android device.

---

### FIX 24 — AdMob release IDs передаються через --dart-define, не хардкод

**Файли:**
- `ios/Runner/Info.plist` — `GADApplicationIdentifier`
- `android/app/src/main/AndroidManifest.xml` — `com.google.android.gms.ads.APPLICATION_ID`
- `env.json` — `ADMOB_APP_ID_IOS`, `ADMOB_APP_ID_ANDROID`
- `lib/src/core/services/ad_service.dart` — banner/interstitial unit IDs

**Проблема:** Якщо production AdMob IDs хардкодом у `Info.plist` / `AndroidManifest.xml` — вони потраплять у git історію і публічний репозиторій (якщо колись запушиш). Плюс неможливо окремо білдити debug/staging з test IDs. Крадіжка Google AdSense session не страшна (ID публічний), але ASO/brand-аналітика — ні.

**Fix:**

1. У `env.json`:
```json
{
  "ADMOB_APP_ID_IOS": "ca-app-pub-XXXX~YYYY",
  "ADMOB_APP_ID_ANDROID": "ca-app-pub-XXXX~ZZZZ",
  "ADMOB_BANNER_IOS": "ca-app-pub-...",
  "ADMOB_BANNER_ANDROID": "ca-app-pub-...",
  "ADMOB_INTERSTITIAL_IOS": "ca-app-pub-...",
  "ADMOB_INTERSTITIAL_ANDROID": "ca-app-pub-..."
}
```

2. У `Info.plist` замінити hardcoded:
```xml
<key>GADApplicationIdentifier</key>
<string>$(ADMOB_APP_ID_IOS)</string>
```

3. У `AndroidManifest.xml`:
```xml
<meta-data
  android:name="com.google.android.gms.ads.APPLICATION_ID"
  android:value="${ADMOB_APP_ID_ANDROID}" />
```

4. `android/app/build.gradle` — передати в `manifestPlaceholders`:
```gradle
android {
    defaultConfig {
        manifestPlaceholders = [
            ADMOB_APP_ID_ANDROID: project.findProperty('ADMOB_APP_ID_ANDROID') ?: 'ca-app-pub-3940256099942544~3347511713'  // test fallback
        ]
    }
}
```

5. iOS — вбудоване `--dart-define-from-file=env.json` + `user-defined build settings` в xcodeproj.

**Acceptance:** `grep "ca-app-pub-" ios/ android/app/src/main/ -R` не повертає production IDs.

---

### FIX 25 — pubspec.yaml description

**Файл:** `medterms_app/pubspec.yaml` рядок 2 (приблизно)

**Проблема:** зараз стоїть default placeholder `A new Flutter project.` або аналог. Це видно в `flutter pub publish` (якщо колись), в `dart info`, в IDE tooltips. Не блокер, але виглядає як abandoned project.

**Fix:**

```yaml
name: medterms_app
description: "MedTerms — medical German terminology for FSP exam preparation. 2934 terms with audio, spaced repetition, and Bundesland-specific filtering."
publish_to: "none"
version: 1.0.0+1
```

**Acceptance:** `grep "A new Flutter" pubspec.yaml` повертає 0.

---

## Порядок виконання (не плутати)

### Фаза 1 — Безпека (обов'язково ДО будь-якого білду)
- [ ] FIX 1 — Subscriptions RLS
- [ ] FIX 2 — RevenueCat webhook
- [ ] FIX 3 — Email functions internal secret
- [ ] FIX 4 — auth-hook signature check
- [ ] FIX 5 — handle_new_user trigger
- [ ] FIX 6 — RevenueCat keys в env
- [ ] FIX 7 — avatars DELETE policy
- [ ] FIX 8 — .vscode/launch.json unignore

### Фаза 2 — Store blockers (обов'язково ДО submit)
- [ ] FIX 9 — iOS Info.plist keys
- [ ] FIX 10 — Sign in with Apple
- [ ] FIX 11 — Android release signing
- [ ] FIX 12 — AndroidManifest permissions
- [ ] FIX 13 — targetSdk ≥ 34
- [ ] FIX 14 — In-app delete account UI
- [ ] FIX 15 — Screenshots + metadata + hosted privacy/terms

### Фаза 3 — Продуктова якість (бажано ДО submit, інакше ДО маркетингу)
- [ ] FIX 16 — FSRS рішення (A або B)
- [ ] FIX 17 — Audio offline UX
- [ ] FIX 18 — Payment tests
- [ ] FIX 19 — UMP consent verification
- [ ] FIX 20 — God-pages refactor (post-launch)

### Фаза 4 — Code review findings (до маркетингу)
- [ ] FIX 21 — Core → Features layer violations
- [ ] FIX 22 — Router refresh on subscription change
- [ ] FIX 23 — Paywall guard bypass scenarios
- [ ] FIX 24 — AdMob release IDs via --dart-define
- [ ] FIX 25 — pubspec.yaml description

---

## Чекліст до submit (acceptance)

### Backend
- [ ] `select * from pg_policies where tablename='subscriptions'` → тільки SELECT для authenticated
- [ ] `curl -X POST ... /functions/v1/revenuecat-webhook` без secret → 401
- [ ] `curl -X POST ... /functions/v1/send-welcome-email` без internal secret → 403
- [ ] Тестова RC покупка (sandbox) → `subscriptions.status='active'` через 2 сек

### Flutter
- [ ] `flutter build ios --release --dart-define-from-file=env.json` → success
- [ ] `flutter build appbundle --release --dart-define-from-file=env.json` → success, підписаний upload key
- [ ] `flutter test` → всі pass
- [ ] `flutter analyze` → 0 warnings/errors

### Store
- [ ] Хостинг privacy.html + terms.html → публічний URL відкривається
- [ ] App Store Connect: метадані + скріншоти + демо-акаунт для ревьюера
- [ ] Google Play Console: Data Safety form заповнена, release track = Internal testing
- [ ] TestFlight / Internal Testing: 3+ людей пройшли реєстрацію + покупку

---

## Примітки

- Всі SQL-патчі ідемпотентні (`drop ... if exists`, `create ... if not exists`). Можна запускати повторно.
- Перед FIX 1 зробити бекап `subscriptions` таблиці якщо там є реальні рядки: `create table subscriptions_backup_20260417 as select * from subscriptions`.
- Service Role Key ніколи не заходить в клієнт. Тільки в Edge Functions через `Deno.env`.
- Секрети Supabase: `supabase secrets set KEY=value` — завантажується в `Deno.env.get`, не в env.json.
- Після фікс 10 (Sign in with Apple) — потрібно новий build + resubmit у TestFlight, бо entitlements у signed IPA.
