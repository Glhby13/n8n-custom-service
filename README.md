# n8n-git-service

Versioning dan rollback berbasis GitLab untuk workflow **n8n yang sudah dipublish** (n8n Community Edition 2.28.6, deployment `n8n-new`).

Author / Agent: Claude Code (Opus 5.5)
Repo: `https://gitlab.devops.btn.co.id/platform/n8n-git-service`

**Ringkasnya:**

- Setiap kali user menekan **Publish** di n8n, service menyimpan workflow itu ke GitLab sebagai satu file `<workflow-id>.json`. Riwayat commit Git menjadi riwayat versi.
- Panel **Versions** di editor n8n menampilkan versi dari GitLab. User bisa **Restore** versi lama lalu **Publish** untuk rollback, tanpa batas "1 day" milik n8n Community.

Prinsip yang dijaga:

- **n8n tidak diubah sama sekali**: tidak ada perubahan source, image, database, maupun values/Ingress `n8n-new`.
- Service **tidak pernah** membaca database n8n atau `N8N_ENCRYPTION_KEY`.
- **Nilai rahasia credential n8n tidak disimpan di Git.** Yang disimpan hanya referensinya (`{id, name}`).
- **Riwayat Git tidak pernah ditulis ulang.** Tidak ada reset, revert, atau force push. Rollback selalu menghasilkan commit **baru**.

---

## Daftar isi

1. [Apa yang dibangun](#1-apa-yang-dibangun)
2. [Arsitektur](#2-arsitektur)
3. [Cara kerja: dari Publish ke commit GitLab](#3-cara-kerja-dari-publish-ke-commit-gitlab)
4. [Format file di GitLab](#4-format-file-di-gitlab)
5. [Kenapa n8n bisa membaca GitLab (panel Versions)](#5-kenapa-n8n-bisa-membaca-gitlab-panel-versions)
6. [Cara pakai](#6-cara-pakai)
7. [REST API service](#7-rest-api-service)
8. [Konfigurasi (environment variable)](#8-konfigurasi-environment-variable)
9. [Deploy dari nol](#9-deploy-dari-nol)
10. [Rilis, milestone, dan rollback service](#10-rilis-milestone-dan-rollback-service)
11. [Operasional dan troubleshooting](#11-operasional-dan-troubleshooting)
12. [Keamanan](#12-keamanan)
13. [Batasan yang diketahui](#13-batasan-yang-diketahui)
14. [Pengembangan lokal dan testing](#14-pengembangan-lokal-dan-testing)
15. [Struktur repo](#15-struktur-repo)
16. [Riwayat perubahan](#16-riwayat-perubahan)

---

## 1. Apa yang dibangun

| Bagian | Isi | Lokasi |
|---|---|---|
| Microservice 1: `git-sync-service` | Poller publish, sinkron ke GitLab/GitHub, API versi/rollback, proxy riwayat untuk panel Versions n8n (`/rest/workflow-history`) | `cmd/git-sync-service` |
| Microservice 2: `sharing-service` | Paywall bypass & granular workflow sharing via native UI modal n8n (`/rest/workflows/:id/share` dan `/rest/settings`) | `cmd/sharing-service` |
| Microservice 3: `auth-service` | Gerbang SSO OIDC Keycloak (`n8n-lab`, role `n8n-access`), JIT auto-provisioning, dan Account Takeover / Mapping akun lokal lama | `cmd/auth-service` |
| Image | Multi-target scratch Go binary (`harbor.lab.local/n8n-custom-service/<service>:<sha8>`, uid 65532, < 15 MB) | `Dockerfile` |
| CI | Jenkins multibranch `n8n-custom-service`: lint, test, kaniko build 3 microservices & push ke Harbor, bump tag manifest | `Jenkinsfile` |
| Helm Base | Generic base chart `helm-base-lab/n8n-custom-service` (Deployment, Service, Ingress) | `helm-base-lab/n8n-custom-service` |
| Values dev | Manifest per microservice di `lab-manifest/n8n-custom-service/` (`git-sync-service`, `sharing-service`, `auth-service`) | `helm-values-lab/lab-manifest/n8n-custom-service` |
| ArgoCD | ApplicationSet `lab-dev-n8n-custom-services` (AppProject khusus `lab-n8n-custom-projects`, `prune`+`selfHeal`, sama seperti kantor) menghasilkan 3 aplikasi: `git-sync-service`, `sharing-service`, `auth-service` | `argocd-gitops-lab` |

## 2. Arsitektur

```
                     Browser user (editor n8n.dev.btn.co.id)
                       │                               │
        semua path lain│                               │ /rest/workflow-history/*
                       ▼                               ▼   (Ingress n8n-git-service,
            ┌─────────────────────┐        ┌──────────────────────────────┐  path lebih spesifik)
            │  n8n-dev (n8n-new)  │◄───────│      n8n-git-service         │
            │  platform-dev       │  REST  │      platform-dev, 1 replika │
            │  /api/v1 (API key)  │ internal│ ┌── poller (tiap 10 s)       │
            │  /rest  (sesi user) │  + API │ ├── sinkron publish → Git    │
            └─────────────────────┘  publik│ ├── API /api/v1 (bearer)     │
                                           │ └── history proxy (sesi n8n) │
                                           └──────────────┬───────────────┘
                                                          │ GitLab REST API v4
                                                          ▼
                     gitlab.devops.btn.co.id  platform/n8n-git-sync/{n8n-pluto, n8n-ai}
                     branch main, satu file <workflow-id>.json per workflow
```

Tiga jalur kerja:

1. **Publish → Git** (otomatis). Poller membaca n8n lewat **API publik** (`X-N8N-API-KEY`), lalu menulis ke GitLab lewat **REST API** (`PRIVATE-TOKEN`).
2. **Panel Versions n8n → Git** (interaktif). Editor n8n meminta riwayat versi ke `/rest/workflow-history/*`. Ingress mengarahkan path itu ke service, dan service menjawab dari GitLab. Hak akses dicek ke n8n memakai sesi user itu sendiri.
3. **API rollback** (opsional, untuk otomasi). `POST /api/v1/workflows/{id}/rollback` memulihkan versi lewat API publik n8n (PUT + activate).

## 3. Cara kerja: dari Publish ke commit GitLab

### 3.1 Membedakan autosave dan Publish

n8n 2.x menyimpan dua penanda versi pada setiap workflow:

| Field | Arti | Berubah saat |
|---|---|---|
| `versionId` | **draft** saat ini | setiap autosave/edit |
| `activeVersion.versionId` | snapshot yang **dipublish** (live) | hanya saat Publish |

API publik n8n tidak punya webhook atau event "workflow dipublish". Karena itu service **polling** `GET /api/v1/workflows` (semua halaman, `excludePinnedData=true`) setiap `POLL_INTERVAL` (dev: **10 detik**). Service mengingat `workflowId → activeVersion.versionId` di memori. **Sinkron hanya terjadi kalau `activeVersion.versionId` berubah**, jadi autosave tidak pernah menghasilkan commit.

- Workflow yang tidak pernah dipublish, di-unpublish, atau diarsipkan (`activeVersion == null`) tidak pernah di-commit.
- **Saat pod start** (`SYNC_ON_STARTUP=true`), semua workflow yang sedang published dicocokkan dengan HEAD Git. Kalau isinya sama, tidak ada commit, sehingga restart tidak membuat commit dobel. Publish yang terjadi saat service mati akan tercatat di sini.
- Kalau n8n tidak bisa dihubungi, poller memakai backoff eksponensial (maks. 5 menit) dengan jitter. Error sementara GitLab/n8n dicoba lagi di putaran berikutnya. Error permanen untuk satu versi (owner tidak termapping, data tidak valid) dicatat sekali.

### 3.2 Menentukan repo: pemetaan owner

Owner workflow adalah entri `shared[]` dengan `role = workflow:owner`. Nama project personal n8n berbentuk `Nama Depan Belakang <email>`. `OWNER_MAPPINGS` mencocokkan `n8nUser` (tanpa membedakan huruf besar/kecil, spasi dirapikan) dengan salah satu dari:

- nama project lengkap,
- bagian namanya saja,
- email,
- id project.

```json
[{"n8nUser":"admin psa","repository":"platform/n8n-git-sync/n8n-pluto"},
 {"n8nUser":"gen-ai itpd","repository":"platform/n8n-git-sync/n8n-ai"}]
```

- Kalau owner tidak ada di daftar, workflow **tidak di-commit**. Log audit mencatat `owner unmapped (owner project "…")`, dan nama di tanda kutip itu bisa langsung dipakai untuk menambah mapping. Tidak ada repo cadangan.
- Repo **hanya** berasal dari konfigurasi server. Tidak ada API yang menerima repo, path, atau URL dari pemanggil.

### 3.3 Menulis ke GitLab

1. Bangun definisi workflow dari **versi yang dipublish** (`activeVersion.nodes/connections/nodeGroups`), bukan dari draft. Nama, settings, meta, dan tags diambil dari objek workflow.
2. Sanitasi dan kanonikalisasi (lihat [§4](#4-format-file-di-gitlab)).
3. Baca `<id>.json` di HEAD `main`. Kalau isinya identik, tidak ada commit (`changed:false`).
4. Kalau berbeda, commit lewat `POST /projects/:id/repository/commits` dengan satu aksi `create`/`update`.
   - Update membawa `last_commit_id` (optimistic locking): GitLab menolak kalau file berubah setelah dibaca.
   - Saat terjadi konflik, service membaca ulang dan membandingkan lagi, maksimal `MAX_COMMIT_RETRIES` kali. Commit orang lain tidak pernah ditimpa.
5. Pesan commit:
   ```
   <nama workflow>

   <deskripsi dari kolom "Describe changes" di dialog Publish n8n, bila diisi>

   N8n-Version-Name: <nama versi dari dialog Publish, mis. "Version a2635b12">
   N8n-Version-Id: <activeVersion.versionId>
   N8n-Workflow-Id: <workflow-id>
   ```
   - Judul commit hanya nama workflow. Id-nya ada di trailer `N8n-Workflow-Id` dan di nama file. `<workflow-id>` adalah ID workflow n8n (terlihat di URL `n8n.dev.btn.co.id/workflow/<id>`), dibuat n8n saat workflow dibuat dan tidak berubah meski workflow di-rename. Karena itu nama file Git memakai id ini.
   - Nama versi dan deskripsi dibaca dari API publik n8n (`GET /workflows/{id}/{versionId}`).
   - Kalau deskripsi diisi, deskripsi juga diposting sebagai **komentar commit** di GitLab.
   - Kalau isi yang sama dipublish ulang dengan deskripsi, tidak ada commit baru. Deskripsi itu diposting sebagai komentar "Dipublish ulang dari n8n tanpa perubahan isi" pada commit HEAD, satu kali per versi n8n.
   - Kegagalan memposting komentar hanya dicatat di log dan tidak menggagalkan sinkron.
   - Trailer `N8n-Version-Id` mengaitkan commit dengan versi n8n. Panel Versions memakainya untuk badge "(Published)" dan untuk mencocokkan versi. Deskripsi commit ditampilkan sebagai deskripsi entri `GitLab <sha7>` di panel.
   - Commit lama memakai judul `chore(n8n): publish workflow <nama> (<id>)` atau `<nama> (<id>)`.

## 4. Format file di GitLab

Satu workflow = satu file `<workflow-id>.json` di root repo. Format JSON-nya kanonik: key terurut, indentasi 2 spasi, newline di akhir, dan teks angka dipertahankan. Akibatnya, perbedaan format saja tidak pernah membuat commit.

| Disimpan | Sengaja dibuang |
|---|---|
| `id`, `name`, `nodes`, `connections`, `settings`, `meta`, `tags` (nama), `nodeGroups` (bila ada), `formatVersion` | `pinData`, `staticData`, `createdAt`, `updatedAt`, `versionId`, `activeVersion`, `shared`, `active`, `isArchived`, `triggerCount`, `authors` |

- **Credential**: di setiap node hanya disimpan referensi `{id, name}`. Nilai rahasia credential memang tidak pernah dikirim API n8n.
- **Teks multi-baris** di parameter node (kode Code node `jsCode`/`pythonCode`, SQL, HTML, prompt, sticky note) disimpan per baris:
  ```json
  "jsCode": { "__lines__": [ "// komentar", "const a = 1;", "return [{ json: { a } }];" ] }
  ```
  Dengan begitu, perubahan satu karakter di kode tampil sebagai **satu baris** diff di GitLab. Saat dipulihkan, baris-baris itu digabung kembali dengan `\n` sehingga teks kembali persis sama (lossless, ada tesnya). Commit lama yang masih menyimpan kode dalam satu baris tetap bisa dipulihkan.
- **Redaksi** (opsional): nilai parameter yang key-nya ada di `REDACT_PARAMETER_KEYS` diganti `__REDACTED__`. Saat restore, nilainya diisi lagi dari workflow yang ada di n8n saat ini (dicocokkan per id node). Kalau tidak bisa diisi, restore ditolak supaya workflow tidak rusak.
- **Nama workflow** selalu diambil dari objek workflow. Endpoint versi n8n 2.28.6 mengembalikan label versi ("Version 3ae8d960"), bukan nama workflow, jadi tidak dipakai.
- **`formatVersion`** menandai cara file ditulis (sekarang `2`). Field ini tidak pernah dikirim ke n8n saat restore. Semua format lama tetap bisa di-Restore.

### 4.1 Migrasi format (sekali jalan)

Kalau cara penulisan file berubah, misalnya ada field baru:

1. Ubah kode penulisan file di `internal/workflow`.
2. Naikkan `FormatVersion` di `internal/workflow/format.go` dan tambahkan catatannya di `FormatNotes`.
3. Tambahkan tes bahwa file format sebelumnya tetap bisa di-Restore.
4. Buat tag milestone di commit yang sedang live, lalu push.

Saat rollout, rekonsiliasi start (`SYNC_ON_STARTUP=true`) menulis ulang setiap workflow **published** satu kali.

- Service membandingkan isi lama dan baru dalam bentuk restore. Yang diabaikan hanya `formatVersion`, `__lines__` vs satu string, urutan key, dan indentasi.
- Kalau isinya sama, commit diberi deskripsi `Format file diperbarui ke formatVersion N: <catatan>. Isi workflow tidak berubah.`, tanpa komentar Publish.
- Kalau ada perubahan isi yang sebenarnya, commit diberi pesan publish biasa.
- Restart berikutnya tidak membuat commit lagi.

Riwayat format:

| formatVersion | Isi |
|---|---|
| (tanpa) | file awal: kode satu string, judul `chore(n8n): publish workflow …` |
| 2 | `__lines__`, `nodeGroups`, judul = nama workflow, trailer `N8n-*` |


## 5. Kenapa n8n bisa membaca GitLab (panel Versions)

Bagian ini menjelaskan bagaimana panel **Versions** bawaan n8n bisa menampilkan commit GitLab tanpa mengubah n8n.

### 5.1 Temuan dari editor n8n 2.28.6

Bundle JavaScript editor n8n diperiksa (read-only, `docs/discovery-n8n-2.28.6.md`). Hasilnya:

- Panel Versions mengambil data dari **REST internal** n8n di bawah `/rest/workflow-history/workflow/{id}`:
  - `GET ...?take&skip`: daftar versi
  - `GET .../version/{versionId}`: isi satu versi (nodes, connections, nodeGroups)
  - `.../versions` (batch), `.../publish-timeline`, `.../versions/{versionId}` (ubah nama)
- **Tombol Restore berjalan di browser.** Editor mengambil isi versi lewat `GET .../version/{versionId}`, lalu menyimpannya sebagai draft lewat API n8n biasa dengan sesi user. Tombol **Compare** juga memakai endpoint yang sama.
- Batas "1 day" hanya teks footer dari lisensi. Pemangkasan riwayat terjadi di server n8n.

Kesimpulannya, kalau endpoint daftar versi dan isi versi dijawab dari GitLab, tombol Restore dan Compare bawaan n8n otomatis bekerja di atas versi GitLab. Izin, credential, dan penyimpanan tetap ditangani n8n sendiri.

### 5.2 Bagaimana request dialihkan

ingress-nginx memilih **prefix path terpanjang**. Chart ini memasang Ingress kedua untuk host `n8n.dev.btn.co.id`, khusus path `/rest/workflow-history`, yang menuju service ini. Semua path lain tetap ke Ingress n8n (`/`). Tidak dipakai snippet annotation (dilarang di cluster ini), dan Ingress milik `n8n-new` tidak diubah. Pola yang sama dipakai Portal untuk `/portal-sso/` di host yang sama.

### 5.3 Autentikasi dan otorisasi

Service tidak punya login sendiri. Editor otomatis mengirim cookie sesi `n8n-auth` dan header `browser-id` (sesi n8n terikat ke browser-id). Service lalu:

1. Meneruskan **hanya** cookie `n8n-auth` dan `browser-id`, **hanya** ke `N8N_BASE_URL` di dalam cluster.
2. Bertanya ke n8n `GET /rest/workflows/{id}` dengan sesi tersebut. Kalau jawabannya **200**, user memang boleh membuka workflow itu, dan barulah isi Git dikirim.
3. Kalau n8n menolak (401/403/404), jawaban n8n diteruskan apa adanya.

Keputusan izin di-cache 30 detik per hash(sesi + workflow). Cookie tidak pernah dicatat di log maupun disimpan. Dengan cara ini, hanya user yang bisa membuka workflow di n8n (owner, yang diberi share, atau admin) yang bisa melihat dan me-restore versi GitLab-nya. Restore sendiri tetap disimpan oleh n8n dengan izin user tersebut.

### 5.4 Isi panel (`HISTORY_PROXY_MODE`)

| Mode | Isi daftar Versions |
|---|---|
| `git-only` (**default, dipakai di dev**) | commit GitLab, terbaru di atas, masing-masing bernama `GitLab <sha7>` dengan deskripsi "<pesan commit> · Restore lalu Publish untuk rollback". Kalau draft yang sedang diedit **berbeda** dari versi published, satu entri **"Draft saat ini (belum dipublish)"** ditaruh paling atas (seperti n8n bawaan), sehingga Restore pada versi published tetap tersedia. Draft/autosave lama lainnya tidak ditampilkan. |
| `merged` | versi n8n sendiri (draft/autosave) + commit GitLab. Commit yang trailer-nya cocok dengan versi n8n yang masih ada ditampilkan sekali sebagai versi n8n |

Detail:

- **`versionId` entri GitLab** memakai nilai trailer `N8n-Version-Id`. Commit lama tanpa trailer memakai `git-<sha>`. Kalau beberapa commit mencatat versi n8n yang sama (misalnya commit migrasi format setelah commit publish), hanya commit **terbaru** yang memakai id itu; yang lebih lama memakai `git-<sha>`.
- **Badge "(Published)"** muncul otomatis pada commit yang `versionId`-nya sama dengan versi yang sedang live di n8n. Kalau isi yang sama dipublish ulang (misalnya setelah Restore versi published lalu Publish), n8n membuat id versi baru tetapi service tidak membuat commit karena isinya identik (`result: unchanged`). Service mencatat pasangan "versi live ↔ commit HEAD" dari setiap sinkron yang berhasil, jadi commit HEAD tetap ditandai "(Published)". Catatan ini disimpan di memori dan dibangun ulang oleh rekonsiliasi saat start.
- **`GET .../version/{versionId}`**: kalau versinya masih ada di n8n, jawaban n8n diteruskan. Kalau tidak, isinya diambil dari GitLab. Teks `__lines__` digabung lagi dan nilai yang diredaksi diisi dari workflow saat ini.
- **Fail-open**: untuk workflow yang owner-nya tidak termapping, saat GitLab error, dan untuk endpoint lain di bawah prefix (publish-timeline, rename, batch), request diteruskan ke n8n apa adanya. Panel berperilaku seperti biasa.

## 6. Cara pakai

### 6.1 Menyimpan versi (otomatis)

Edit workflow seperti biasa, lalu klik **Publish**. Dalam sekitar 10 detik muncul commit `chore(n8n): publish workflow …` di repo owner. Autosave tanpa Publish tidak menghasilkan commit.

### 6.2 Melihat dan membandingkan versi

Buka workflow di n8n, lalu klik ikon jam (**Versions**). Daftar berisi `GitLab <sha7>`. Klik salah satu untuk melihat canvas versi tersebut, atau gunakan **Compare** untuk membandingkan dua versi. Di GitLab, buka `platform/n8n-git-sync/<repo>` → Commits → pilih file `<id>.json` untuk diff per baris.

### 6.3 Rollback dari n8n (cara utama)

1. Panel **Versions** → pilih `GitLab <sha7>` yang diinginkan.
2. **⋮ → Restore**. Isi versi itu menjadi **draft**, dan versi yang live belum berubah (n8n menampilkan keterangan ini).
3. Periksa, lalu klik **Publish**.
4. Dalam sekitar 10 detik, poller membuat **commit baru** di GitLab yang isinya sama dengan versi yang dipulihkan:
   ```
   A → B → C            restore B lalu Publish
   A → B → C → D        (isi D == B; riwayat tidak ditulis ulang)
   ```

Catatan: n8n selalu menyembunyikan tombol Restore pada entri **paling atas**. Kalau Anda sudah Restore versi lama tetapi batal dan ingin kembali ke versi yang sedang live, entri paling atas adalah "Draft saat ini (belum dipublish)". Pilih `GitLab <sha7> (Published)` di bawahnya lalu **Restore**.

### 6.4 Rollback lewat API (otomasi)

Service tidak punya Ingress untuk `/api/v1`, jadi API dipanggil dari dalam cluster, misalnya Rancher → cluster `local` → **Kubectl Shell**:

```bash
T=$(kubectl -n platform-dev get secret n8n-git-service-secret -o jsonpath='{.data.SERVICE_API_TOKEN}' | base64 -d)
S=http://n8n-git-service.platform-dev.svc:8080
W=<workflow-id>          # dari URL n8n: /workflow/<id>

# riwayat
curl -s -H "Authorization: Bearer $T" $S/api/v1/workflows/$W/versions | jq -r '.[] | "\(.commitSha)  \(.timestamp)  \(.message)"'

# versi published saat ini (aman diulang; changed:false kalau Git sudah sama)
CUR=$(curl -s -X POST -H "Authorization: Bearer $T" $S/api/v1/workflows/$W/publish | jq -r .publishedVersion)

# rollback: PUT + activate di n8n, Git tidak disentuh; poller lalu menulis commit baru
curl -s -X POST -H "Authorization: Bearer $T" \
  -d "{\"commitSha\":\"<sha 40 karakter>\",\"expectedPublishedVersion\":\"$CUR\"}" \
  $S/api/v1/workflows/$W/rollback | jq
```

Bedanya dengan Restore di n8n: API **langsung mem-publish** versi yang dipulihkan. Kalau `expectedPublishedVersion` sudah tidak cocok (ada publish lain di sela-sela), API menolak dengan **409**.

### 6.5 Autentikasi SSO, Keycloak Role Admin & Transfer Kepemilikan (auth-service)

Login SSO (Keycloak) mengamankan akses ke n8n Community dengan pemetaan identitas enterprise dan manajemen role otomatis:

1. **Sinkronisasi Role Admin Otomatis dari Keycloak (Zero Terminal)**:
   - Keycloak Client `n8n-lab` menyediakan client role: `n8n-access`, `n8n-admin`, dan `n8n-user`.
   - Group Keycloak:
     - Parent `n8n` $\rightarrow$ client role `n8n-access` (izin masuk).
     - Child `n8n-admin` $\rightarrow$ client role `n8n-admin`.
     - Child `n8n-user` $\rightarrow$ client role `n8n-user`.
   - Saat login SSO (`/sso/callback`), service membaca klaim role dari token OIDC:
     - User dengan role **`n8n-admin`** otomatis diset sebagai **`global:admin`** di n8n (bisa kelola Settings, Users, Community Nodes, dsb.).
     - User dengan role **`n8n-user`** diset sebagai **`global:member`**.
     - Akun root awal **`global:owner`** diproteksi agar tidak terdowngrade.
   - Admin cukup memasukkan atau mengeluarkan user dari group `n8n-admin` di Keycloak.

2. **Security Hardening: Nonaktifkan Mutasi di Exec Pod**:
   - Untuk mencegah modifikasi sepihak tanpa audit trail, perintah mutasi CLI di dalam container (`map-user`, `unmap`) **dinonaktifkan** (`SECURITY ERROR`).
   - CLI container hanya melayani perintah read-only: `/app list-users` dan `/app list-mappings`.
   - Seluruh mutasi data akun dan transfer aset **wajib** melalui REST API terotentikasi Bearer Token.

3. **Token-Based Identity (Bearer Token) untuk Postman / API Client**:
   - Token rahasia admin didefinisikan pada Secret `n8n-auth-service-secret` dengan key `ADMIN_API_TOKEN`.
   - Setiap panggilan API wajib menyertakan header:
     `Authorization: Bearer <ADMIN_API_TOKEN>`
   - Validasi dilakukan menggunakan *constant-time comparison* (`crypto/subtle`).

4. **Panduan Lengkap REST API auth-service (Postman & cURL)**:

   Semua endpoint administratif `auth-service` berada di bawah prefix `/admin/api/v1/*` (atau `/admin/api/*` untuk kompatibilitas).

   #### A. Konfigurasi Autentikasi & URL di Postman
   - **Base URL**:
     - **Lab**: `https://n8n.lab.local`
     - **Kantor**: `https://n8n.dev.btn.co.id`
   - **Authorization Tab**:
     - Masuk ke tab **Authorization** pada Postman.
     - Pilih **Type**: `Bearer Token`.
     - Masukkan nilai **Token**: `<ADMIN_API_TOKEN>` (diambil dari Secret `n8n-auth-service-secret`, misal `N8nAdminApiTokenLab2026#` di lab atau token kantor).
     - *Catatan:* Tidak memerlukan username dan password.
   - **Postman Settings Wajib (`Cmd + ,`)**:
     - Tab **Proxy**: Matikan *Use system proxy* (OFF) agar request ke domain internal/lab tidak dibelokkan ke luar.
     - Tab **General**: Matikan *SSL certificate verification* (OFF) jika sertifikat SSL lokal bertipe internal CA.

   ---

   #### B. Endpoint 1: Menampilkan Daftar Pengguna (`GET /admin/api/v1/users`)
   Melihat seluruh pengguna yang terdaftar di n8n, hak akses aktif mereka (`global:owner`, `global:admin`, `global:member`), status aktif/disabled, dan ID personal project mereka.

   - **Method**: `GET`
   - **Path**: `https://<host-n8n>/admin/api/v1/users`
   - **Header**: `Authorization: Bearer <ADMIN_API_TOKEN>`
   - **Contoh Response (`200 OK`)**:
     ```json
     {
       "data": [
         {
           "id": "22735a0f-67ab-4505-aa00-4af6a894ccec",
           "email": "admin@lab.local",
           "first_name": "Admin",
           "last_name": "Lab",
           "role": "global:owner",
           "disabled": false,
           "personal_project_id": "x6JDdjz5gmSTfDqu",
           "created_at": "2026-10-09T22:03:30.911+07:00"
         },
         {
           "id": "caa9b823-3fa1-4314-8a8a-ebaae7737bcd",
           "email": "user@lab.local",
           "first_name": "User",
           "last_name": "AD",
           "role": "global:admin",
           "disabled": false,
           "personal_project_id": "6pXCEsnhww3L9n80",
           "created_at": "2026-10-16T22:43:29.171+07:00"
         }
       ]
     }
     ```

   ---

   #### C. Endpoint 2: Transfer Kepemilikan Workflow & Kredensial (`POST /admin/api/v1/transfer-ownership`)
   Memindahkan hak milik workflow dan kredensial antar akun (misal dari akun developer lokal lama ke akun AD baru, atau pelimpahan tugas antar user AD).

   - **Method**: `POST`
   - **Path**: `https://<host-n8n>/admin/api/v1/transfer-ownership`
   - **Header**:
     - `Authorization: Bearer <ADMIN_API_TOKEN>`
     - `Content-Type: application/json`

   **Skenario 1: Memindahkan SELURUH Workflow & Credentials (Account Takeover)**:
   ```json
   {
     "from_email": "developer-lama@btn.co.id",
     "to_email": "developer-baru@btn.co.id",
     "scope": "all",
     "disable_source": false
   }
   ```
   *Parameter:*
   - `from_email` *(string, required)*: Email pemilik aset saat ini.
   - `to_email` *(string, required)*: Email penerima aset baru (otomatis di-provisioning jika user belum pernah login, sehingga admin bisa mentransfer kapan saja).
   - `scope` *(string, opsional)*: `"all"` untuk seluruh aset personal (default).
   - `disable_source` *(boolean, opsional)*: `true` jika ingin langsung menonaktifkan akun lama (cocok untuk pegawai resign/mutasi), atau `false` jika akun lama tetap aktif.

   **Skenario 2: Memindahkan SATU Workflow Tertentu Saja**:
   ```json
   {
     "from_email": "user.a@btn.co.id",
     "to_email": "user.b@btn.co.id",
     "scope": "workflow",
     "workflow_id": "PquKXqWxalIuZnzT"
   }
   ```
   *Parameter tambahan:*
   - `workflow_id` *(string, required jika scope = "workflow")*: ID workflow 16-karakter di n8n.

   **Contoh Response (`200 OK`)**:
   ```json
   {
     "status": "success",
     "message": "Successfully transferred 9 workflow(s) and 2 credential(s) from user2@lab.local to user@lab.local",
     "data": {
       "from_email": "user2@lab.local",
       "to_email": "user@lab.local",
       "workflows_transferred": 9,
       "credentials_transferred": 2,
       "source_disabled": false
     }
   }
   ```

   ---

   #### D. Endpoint 3: Ubah Status Pengguna / Enable & Disable (`POST /admin/api/v1/users/{email}/status`)
   Mengaktifkan kembali atau menonaktifkan akun pengguna di n8n.
   *(Sangat berguna pada n8n Community edition karena UI web n8n tidak menyediakan tombol Re-enable untuk akun yang ter-disable).*

   - **Method**: `POST`
   - **Path**: `https://<host-n8n>/admin/api/v1/users/{email}/status`
   - **Header**:
     - `Authorization: Bearer <ADMIN_API_TOKEN>`
     - `Content-Type: application/json`

   **Body Menonaktifkan Akun (Disable)**:
   ```json
   {
     "disabled": true
   }
   ```

   **Body Mengaktifkan Akun Kembali (Enable)**:
   ```json
   {
     "disabled": false
   }
   ```

   **Contoh Response (`200 OK`)**:
   ```json
   {
     "status": "success",
     "message": "User status for elroy21945@btn.co.id updated successfully",
     "data": {
       "email": "elroy21945@btn.co.id",
       "disabled": false
     }
   }
   ```
   *(Proteksi bawaan: Akun root `global:owner` diproteksi dan tidak dapat di-disable).*

   ---

   #### E. Endpoint 4: Hapus Pengguna / Delete User (`DELETE /admin/api/v1/users/{email}`)
   Menghapus akun pengguna dari database n8n secara permanen.

   - **Method**: `DELETE`
   - **Path**: `https://<host-n8n>/admin/api/v1/users/{email}`
   - **Query Parameters**:
     - `force` *(boolean, opsional, default: `false`)*: Jika `false`, penghapusan akan dicegah apabila pengguna masih memiliki workflow aktif di personal project-nya. Jika `force=true`, seluruh workflow dan relasi pengguna akan ikut dibersihkan (cascade).
   - **Header**:
     - `Authorization: Bearer <ADMIN_API_TOKEN>`

   **Contoh Request Aman (Gagal jika masih ada workflow)**:
   `DELETE https://<host-n8n>/admin/api/v1/users/user.lama@btn.co.id`

   *Response jika masih ada workflow (`400 Bad Request`)*:
   ```json
   {
     "error": {
       "code": "cannot_delete_user_with_workflows",
       "message": "Cannot delete user user.lama@btn.co.id: user still owns 3 workflow(s). Transfer ownership first or pass ?force=true to delete permanently"
     }
   }
   ```

   **Contoh Request Force Delete**:
   `DELETE https://<host-n8n>/admin/api/v1/users/user.lama@btn.co.id?force=true`

   *Response Sukses (`200 OK`)*:
   ```json
   {
     "status": "success",
     "message": "User user.lama@btn.co.id deleted successfully",
     "data": {
       "email": "user.lama@btn.co.id",
       "workflows_deleted": 3,
       "credentials_deleted": 1
     }
   }
   ```
   *(Proteksi bawaan: Akun root `global:owner` diproteksi dan tidak dapat dihapus).*

   ---

   #### F. Endpoint 5: Ubah Role Pengguna Manual (`POST /admin/api/v1/users/{email}/role`)
   Mengubah role pengguna secara manual melalui API (opsional/emergency override).

   - **Method**: `POST`
   - **Path**: `https://<host-n8n>/admin/api/v1/users/{email}/role`
   - **Header**:
     - `Authorization: Bearer <ADMIN_API_TOKEN>`
     - `Content-Type: application/json`
   - **Body**:
     ```json
     {
       "role": "global:admin"
     }
     ```
     *(Nilai role yang diizinkan: `"global:admin"` atau `"global:member"`. Akun `global:owner` root instance diproteksi otomatis dari perubahan).*
   - **Contoh Response (`200 OK`)**:
     ```json
     {
       "status": "success",
       "message": "Role for user lab-test3@lab.local updated to global:admin"
     }
     ```

   ---

   #### G. Endpoint Legacy: Account Mapping (`/admin/api/mappings`)
   Disediakan untuk kompatibilitas skrip lama:
   - `GET /admin/api/mappings`: Melihat daftar mapping aktif.
   - `POST /admin/api/mappings`: Membuat mapping pengalihan akun OIDC ke akun lokal.
   - `DELETE /admin/api/mappings/{oidcEmail}`: Menghapus mapping.

   ---

   #### H. Penjelasan Mendalam: Apa yang Terjadi Jika User SSO di-Disable atau di-Delete via API?

   Banyak admin menanyakan apa yang terjadi jika pengguna login via SSO Keycloak, namun di n8n akunnya di-**disable** atau di-**delete** melalui API:

   | Tindakan Admin via API | Status di SSO Keycloak | Apa yang Terjadi Saat User Klik "Sign in with SSO"? |
   |---|---|---|
   | **DISABLE USER** (`POST .../status` `{"disabled":true}`) | Masih aktif & punya role `n8n-access` | **DITOLAK SEKETIKA (HTTP 403 Forbidden)**. Meskipun login Keycloak berhasil, saat Keycloak redirect ke callback `auth-service`, sistem mendeteksi status `disabled = true` di database n8n. Sistem langsung memutus alur login, menolak membuat sesi n8n, dan menampilkan pesan: *"Akses ditolak: Akun telah dinonaktifkan oleh Administrator"*. Status `disabled` tetap terkunci aman dan akun tidak bisa dipakai login. |
   | **ENABLE USER** (`POST .../status` `{"disabled":false}`) | Masih aktif & punya role `n8n-access` | **BERHASIL LOGIN**. Akun kembali aktif normal dan sesi login terbentuk seperti biasa. |
   | **DELETE USER** (`DELETE .../users/{email}`) | Masih aktif & punya role `n8n-access` | **DIBUATKAN AKUN BARU KOSONG (JIT Provisioning)**. Karena data user di database n8n sudah terhapus permanen, saat user login SSO Keycloak, `auth-service` memperlakukannya sebagai pengguna baru pertama kali. Sistem otomatis membuat akun baru dengan personal project kosong (tanpa workflow lama). |

   > [!IMPORTANT]
   > **Rekomendasi Keamanan untuk Admin:**
   > - Jika ingin **mencabut akses pengguna (pegawai mutasi/resign)** tanpa user bisa login ulang dan tanpa membuat akun baru yang liar: **Gunakan fitur DISABLE (`POST /admin/api/v1/users/{email}/status`)** atau **cabut role `n8n-access` pada akun user di Keycloak**.
   > - Hindari sekadar men-DELETE user jika hak akses SSO di Keycloak belum dicabut, karena mekanisme JIT n8n akan mengizinkan pembuatan akun baru saat user login SSO kembali.
   > - Jika user pindah akun atau ganti format email: Selalu jalankan **TRANSFER OWNERSHIP (`POST /transfer-ownership`)** terlebih dahulu sebelum menonaktifkan atau menghapus akun lama!

   ---

   #### I. Format Error Response
   Jika request gagal atau token salah:
   ```json
   {
     "error": "unauthorized",
     "message": "Invalid or missing Bearer token in Authorization header"
   }
   ```
   Status code:
   - `400 Bad Request`: Payload JSON tidak valid, user masih memiliki workflow saat delete tanpa `?force=true`, atau parameter wajib belum terisi.
   - `401 Unauthorized`: Token Bearer tidak disertakan atau token salah.
   - `403 Forbidden`: Tindakan dilarang (misal mencoba mengubah status, role, atau menghapus akun `global:owner`).
   - `404 Not Found`: Email pengguna yang dituju tidak ditemukan di database n8n.
   - `500 Internal Server Error`: Kesalahan internal server atau kegagalan query database.

Catatan: user DB (`lab_worker` di lab, `platform_worker` di kantor) harus boleh `UPDATE` tabel `"user"`, `project`, `shared_workflow`, dan `shared_credentials` di `n8n_db`; kalau `map-user` gagal "permission denied", periksa hak itu. Mengganti `OIDC_CLIENT_SECRET` aman: password terkelola ditimpa setiap login.

## 7. REST API service

Semua `/api/v1/*` wajib memakai `Authorization: Bearer <SERVICE_API_TOKEN>` (dibandingkan constant-time). Kontrak lengkap ada di [api/openapi.yaml](api/openapi.yaml).

| Method | Path | Auth | Keterangan |
|---|---|---|---|
| GET | `/healthz` | — | liveness proses |
| GET | `/readyz` | — | konfigurasi valid. Status poller ikut dilaporkan, tetapi tidak membuat pod "not ready". |
| GET | `/metrics` | — | Prometheus |
| POST | `/api/v1/workflows/{id}/publish` | bearer | sinkron sekarang. Respons berisi `changed`, `commitSha`, `publishedVersion`, … |
| GET | `/api/v1/workflows/{id}/versions` | bearer | riwayat commit file |
| GET | `/api/v1/workflows/{id}/versions/{sha}` | bearer | isi `<id>.json` pada commit itu |
| POST | `/api/v1/workflows/{id}/rollback` | bearer | `{commitSha, expectedPublishedVersion}` |
| GET/… | `/rest/workflow-history/*` | sesi n8n | proxy panel Versions (lihat [§5](#5-kenapa-n8n-bisa-membaca-gitlab-panel-versions)) |

Format error: `{"error":{"code","message"},"requestId"}`.

| HTTP | Kode error |
|---|---|
| 400 | `invalid_request` |
| 401 | (tanpa kode) |
| 404 | `not_found` |
| 409 | `not_published` atau `conflict` |
| 413 | (tanpa kode) |
| 422 | `owner_unmapped` atau `invalid_workflow_data` |
| 429 | (tanpa kode) |
| 502 | `upstream_error` |

## 8. Konfigurasi (environment variable)

Nilai non-rahasia ada di ConfigMap (values Helm). Tiga rahasia diambil dari Secret `n8n-git-service-secret`.

| Variabel | Default | Nilai dev / keterangan |
|---|---|---|
| `N8N_BASE_URL` | wajib | `http://n8n-dev.platform-dev.svc:5678` |
| `N8N_API_KEY` | wajib (Secret) | API key n8n. Scope minimal `workflow:list`, `workflow:read`, `workflow:update`, `workflow:activate` |
| `GITLAB_BASE_URL` | wajib, https | `https://gitlab.devops.btn.co.id` |
| `GITLAB_TOKEN` | wajib (Secret) | group access token `n8n-git-sync` (grup `platform/n8n-git-sync`), role ≥ Developer, scope **`api`** |
| `GITLAB_BRANCH` | `main` | |
| `GITLAB_CA_FILE` | kosong | PEM CA tambahan. Tidak perlu untuk GitLab kantor (sertifikat DigiCert publik) |
| `SERVICE_API_TOKEN` | wajib (Secret, ≥ 16 karakter) | bearer untuk `/api/v1/*` |
| `OWNER_MAPPINGS` | wajib | JSON array (lihat [§3.2](#32-menentukan-repo-pemetaan-owner)) |
| `POLL_ENABLED` | `true` | |
| `POLL_INTERVAL` | `30s` | dev `10s` |
| `SYNC_ON_STARTUP` | `true` | rekonsiliasi saat start |
| `HISTORY_PROXY_ENABLED` | `false` | dev `true`. Butuh Ingress `/rest/workflow-history` |
| `HISTORY_PROXY_MODE` | `git-only` | `git-only` atau `merged` |
| `N8N_AUTH_COOKIE_NAME` | `n8n-auth` | nama cookie sesi n8n |
| `REDACT_PARAMETER_KEYS` | kosong | dev: `password,passwd,apiKey,api_key,token,accessToken,refreshToken,secret,clientSecret,privateKey` |
| `LOG_LEVEL` | `info` | dev `debug` |
| `PORT` | `8080` | |
| `HTTP_TIMEOUT` | `20s` | timeout panggilan keluar |
| `MAX_BODY_BYTES` | `1048576` | |
| `RATE_LIMIT_RPS` | `10` | untuk `/api/v1` |
| `MAX_COMMIT_RETRIES` | `3` | 1..10 |
| `MAX_HISTORY_COMMITS` | `500` | kedalaman riwayat yang dibaca |
| `MAX_WORKFLOW_BYTES` | `8388608` | |
| `N8N_PAGE_SIZE` | `100` | |
| `SHUTDOWN_TIMEOUT_SECONDS` | `20` | |

**Mengubah setting**: edit `app-of-apps/helm-values/platform-manifest/n8n-git-service/values-common.yaml` (berlaku umum) atau `values-env-dev.yaml` (khusus dev), lalu push. ArgoCD akan sync. Perubahan ConfigMap mengubah checksum, sehingga pod otomatis restart.

**Menambah owner/repo baru:**

1. Buat repo di grup `platform/n8n-git-sync`. Pastikan **Protected branches → `main` → Allowed to push and merge: Developers + Maintainers**, dan force push tetap mati.
2. Tambahkan entri ke `OWNER_MAPPINGS` di `values-env-dev.yaml`, lalu push.

Nama owner yang tepat bisa dilihat di log audit `owner unmapped (owner project "…")`.

## 9. Deploy dari nol

Urutan ini yang dipakai saat pertama kali deploy ke dev (`platform-dev`, cluster `onprem-dev-1`).

### 9.1 Prasyarat (manual, sekali)

| Sistem | Langkah |
|---|---|
| GitLab | Group access token `n8n-git-sync` di grup `platform/n8n-git-sync`, role Developer, scope **`api`** (`read/write_repository` saja tidak cukup untuk REST API). Repo `n8n-pluto` dan `n8n-ai` dengan branch `main`. Protected branch `main` mengizinkan push untuk **Developers + Maintainers**. Tanpa ini, commit ditolak `403 You are not allowed to push into this branch`. |
| n8n | API key untuk service (Settings → n8n API) dengan scope workflow di atas |
| Kubernetes (Rancher, ns `platform-dev`) | Secret **`n8n-git-service-secret`** dengan key `GITLAB_TOKEN`, `N8N_API_KEY`, `SERVICE_API_TOKEN` |
| Harbor (`harbor.dev.btn.co.id`) | Project **`n8n-git-service`** (private). Robot pull `robot$n8n-git-service+k8s-pull` (Repository: Pull). Tambahkan project ini ke robot sistem **`robot$jenkins-push`** (izin sama dengan project lain). |
| Kubernetes | Secret dockerconfigjson **`n8n-git-service-harbor-secret`** di `platform-dev` (registry `harbor.dev.btn.co.id`, user robot pull) |
| Jenkins (`sandbox.dev.btn.co.id`) | Multibranch Pipeline **`n8n-git-service`** (Copy from `portal-platform`): source `https://gitlab.devops.btn.co.id/platform/n8n-git-service.git`, credential `gitlab-sandbox`, Script Path `Jenkinsfile`, scan berkala 5 menit, simpan 5 item lama. Tidak perlu Global properties baru. |

Jenkinsfile memakai ulang konfigurasi Jenkins portal-platform:
- `PORTAL_REGISTRY_URL`, `PORTAL_REGISTRY_CREDENTIALS_ID` (`harbor-jenkins-push`)
- `PORTAL_*_IMAGE` (image CI dari Harbor `library`)
- pod template `portal-build`

Default repo manifest adalah `https://gitlab.devops.btn.co.id/platform/app-of-apps/helm-values/platform-manifest.git` dengan credential `PORTAL_MANIFEST_CREDENTIALS_ID`/`gitlab-sandbox`. Semuanya bisa ditimpa lewat env `N8NGIT_*`.

### 9.2 Urutan push

1. `helm-values/platform-manifest` (folder `n8n-git-service/`) dan `helm-base` (chart `n8n-git-service/`). Values harus sudah ada di remote sebelum Jenkins mencoba menaikkan tag.
2. Repo ini, ke `main`. Jenkins menjalankan lint, test, govulncheck, build image `<sha8>`, push ke Harbor, lalu commit `n8n-git-service: image tag <sha8>` ke `platform-manifest`.
3. `argocd-gitops`: tambahkan `- service: n8n-git-service` di ApplicationSet dev. ArgoCD membuat dan menyinkronkan Application.
4. Aktifkan panel Versions:
   - `HISTORY_PROXY_ENABLED: "true"`
   - `ingress.enabled: true` (host `n8n.dev.btn.co.id`, path `/rest/workflow-history`)

   Ini dilakukan **setelah** image yang punya fitur proxy sudah live.

Repo ArgoCD/registrasi repo di `common-k8s-resources/values-controlplane-*` **tidak perlu diubah**, karena `helm-base` dan `platform-manifest` sudah terdaftar. Repo source ini hanya dibaca oleh Jenkins.

### 9.3 Verifikasi setelah deploy

- ArgoCD `platform-n8n-git-service-dev-onprem-dev-1`: Synced/Healthy, pod 1/1.
- Log pod memuat baris `"msg":"starting"` yang berisi mapping, lalu baris `"audit":true` dengan `result` `success`, `unchanged`, atau `skipped`.
- Repo `n8n-pluto`/`n8n-ai` berisi commit baseline (rekonsiliasi saat start).
- Request tanpa login ke `https://n8n.dev.btn.co.id/rest/workflow-history/workflow/<id>` mendapat `401` **dengan** header `X-Request-Id`. Header itu menandakan request dilayani service ini.
- Panel Versions di editor menampilkan `GitLab <sha7>`.

## 10. Rilis, milestone, dan rollback service

- Setiap push ke `main` menghasilkan image `harbor.dev.btn.co.id/n8n-git-service/n8n-git-service:<sha8>`. Jenkins menaikkan `image.tag` di `values-env-dev.yaml`.
- **Milestone** ditandai dengan tag Git annotated di repo ini. Pesan tag mencatat image dan commit manifest yang live saat itu.

| Tag | Commit | Image | Isi |
|---|---|---|---|
| `v0.1.0` | `073941b` | `073941b3` | sinkron publish, API rollback, format `__lines__`, trailer, nodeGroups, panel Versions mode **merged** |
| `v2.0.0` | `517ba13` | `517ba132` | panel Versions **hanya GitLab** (+ draft saat ini bila beda), badge "(Published)" tetap setelah publish ulang isi sama, judul commit = nama workflow, deskripsi Publish di body commit + komentar GitLab, trailer `N8n-Version-Name`/`N8n-Version-Id`/`N8n-Workflow-Id` |

**Rollback service ke milestone**: di `helm-values/platform-manifest/n8n-git-service/values-env-dev.yaml`, isi `image.tag` dengan image milestone (`"517ba132"` untuk v2.0.0, `"073941b3"` untuk v0.1.0) lalu push. Image lama tetap ada di Harbor.

**Mematikan fitur panel Versions saja**: isi `ingress.enabled: false` dan `HISTORY_PROXY_ENABLED: "false"` lalu push. Panel kembali 100% ke perilaku asli n8n, sedangkan sinkron publish ke Git tetap berjalan.

## 11. Operasional dan troubleshooting

- **Log**: JSON (slog). Setiap request membawa `request_id`, dan putaran poller memakai `poll-<n>`. Setiap operasi bisnis menulis satu baris audit (`audit=true`, `operation`, `result`, `workflow_id`, `n8n_user`, `repository`, `commit_sha`, `reason`, `latency_ms`).
- **Metrik** (`/metrics`):
  - `n8n_git_publish_total{result}`
  - `n8n_git_rollback_total{result}`
  - `n8n_git_operation_duration_seconds{operation}`
  - `n8n_git_operation_errors_total{operation,reason}`
  - `n8n_gitlab_requests_total{method,code}`
  - `n8n_n8n_api_requests_total{method,code}`
- **`/readyz`**: berisi `dependencies.poller` (waktu terakhir jalan dan sukses, `consecutiveFailures`, jumlah workflow published).

| Gejala | Penyebab / tindakan |
|---|---|
| Audit `skipped` + `owner unmapped (owner project "…")` | owner belum ada di `OWNER_MAPPINGS`. Tambahkan nama di tanda kutip itu. |
| Audit `skipped` + `not published` | workflow belum dipublish. Normal. |
| `error` + `403 You are not allowed to push into this branch` | protected branch `main` belum mengizinkan Developers push |
| `error` + GitLab `401`/`403 insufficient_scope` | token tidak valid atau tidak ber-scope `api` |
| `conflict` | ada commit lain pada file yang sama. Service sudah mencoba ulang tanpa menimpa. |
| Panel Versions tidak menampilkan `GitLab …` | cek ArgoCD sudah sync, Ingress `/rest/workflow-history` ada, `HISTORY_PROXY_ENABLED=true`, dan owner termapping. Respons yang punya header `X-Request-Id` berarti dilayani service. |
| Panel Versions error 502 | pod service down atau tidak bisa menghubungi n8n. Editor lain tetap normal. Lihat log pod. |
| Restore gagal "GitLab version: … cannot be restored safely" | versi itu berisi nilai `__REDACTED__` yang tidak bisa diisi dari workflow saat ini. Workflow tidak berubah. |
| `ImagePullBackOff` | tag belum ada di Harbor, Secret `n8n-git-service-harbor-secret` belum ada, atau node tidak bisa me-resolve `harbor.dev.btn.co.id` |
| `x509: certificate signed by unknown authority` | set `GITLAB_CA_FILE` (mount CA) |
| Build Jenkins gagal push image | robot `jenkins-push` belum punya akses ke project Harbor `n8n-git-service` |
| Build Jenkins gagal "Update manifest" | `platform-manifest/n8n-git-service/values-env-dev.yaml` belum ada di remote, atau credential tidak punya izin tulis |

## 12. Keamanan

- **Rahasia**: hanya dari env (Secret). Tidak pernah ada di kode, values, ConfigMap, image, atau log.
- **Sesi n8n** (panel Versions): hanya `n8n-auth` + `browser-id` yang diteruskan, dan hanya ke n8n internal. Tidak pernah dicatat atau disimpan. Keputusan izin tetap milik n8n.
- **Log**: key yang mirip rahasia (`authorization`, `token`, `api_key`, `secret`, `password`, `cookie`) diredaksi. Header request dan isi workflow tidak pernah dicatat.
- **Input**:
  - id workflow `^[A-Za-z0-9_-]{1,64}$`, SHA `^[0-9a-fA-F]{40}$`
  - body ≤ 1 MiB dan JSON ketat
  - rate limit untuk `/api/v1`
- **Keluar**:
  - URL hanya dari konfigurasi, redirect dimatikan, timeout
  - TLS selalu diverifikasi (≥ 1.2), dan GitLab wajib https
- **Container**: `FROM scratch`, non-root 65532, root filesystem read-only, semua capability di-drop, seccomp `RuntimeDefault`, token ServiceAccount tidak di-mount.

## 13. Batasan yang diketahui

- **Polling, bukan event.** Ada jeda hingga `POLL_INTERVAL`. Beberapa Publish dalam satu interval tercatat sebagai satu commit (state terakhir).
- **Bergantung pada REST internal n8n** (`/rest/workflow-history`, `/rest/workflows`) untuk panel Versions. Endpoint itu bukan API publik dan bisa berubah saat n8n di-upgrade. Cek ulang setiap upgrade (`docs/discovery-n8n-2.28.6.md`). Kalau rusak, matikan fitur proxy; sinkron ke Git tidak terpengaruh.
- **Nama, settings, meta, dan tags** diambil dari objek workflow, bukan dari versi published (n8n tidak menyimpannya di `activeVersion`). Kalau nama diganti di draft yang belum dipublish, nama baru ikut tercatat pada sinkron berikutnya.
- **Parameter node bisa berisi rahasia yang diketik langsung** (misalnya token di HTTP node atau di kode Code node). Redaksi hanya heuristik berdasarkan nama key, dan rahasia di dalam teks kode tidak terdeteksi. Simpan rahasia di **n8n Credentials** atau env, jangan di parameter atau kode. Isi yang sudah ter-commit tetap ada di riwayat Git, karena riwayat tidak ditulis ulang.
- **Satu API key n8n** dengan scope workflow luas dipakai untuk semua owner. Pemisahan antar-owner bergantung pada `OWNER_MAPPINGS` (sinkron) dan izin n8n (panel Versions).
- **Footer "Version history is limited to 1 day"** tetap tampil karena itu teks lisensi n8n. Versi GitLab tetap tersedia di daftar.
- Pada mode `git-only` hanya draft **saat ini** yang tampil (bila berbeda dari published). Riwayat autosave lainnya tidak tampil; pakai `merged` kalau perlu.
- Restore di panel tidak tersedia untuk entri paling atas (perilaku n8n).
- Kalau `network-isolation` diterapkan ke `platform-dev`, egress ke GitLab (443) harus diizinkan.

## 14. Pengembangan lokal dan testing

```bash
go vet ./...
go test ./...
go test -race ./...
golangci-lint run ./cmd/... ./internal/...
govulncheck ./...          # toolchain Go 1.27.2 (1.27.1 punya CVE stdlib)
docker build -t n8n-git-service:local .
```

Tes memakai `httptest` dan fake di memori, sehingga tidak pernah memanggil n8n atau GitLab asli. Cakupannya:

- kanonikalisasi, sanitasi, `__lines__` lossless, redaksi, `nodeGroups`
- config dan mapping owner
- klien GitLab dan n8n (path, konflik, redirect, timeout, token tidak bocor)
- publish (idempoten, konflik, owner tidak termapping, belum publish, GitLab down)
- poller (autosave diabaikan, rekonsiliasi saat restart)
- rollback A→B→C→D, termasuk 409, SHA tidak valid, JSON rusak, id tidak cocok
- history proxy:
  - mode `git-only`/`merged`, dedupe trailer, paging
  - otorisasi lewat sesi n8n dan cache-nya
  - fail-open, passthrough
- redaksi log

Lingkungan lokal dengan mock n8n + GitLab (HTTPS dengan CA self-signed):

```bash
docker compose -f deploy/local/compose.yml up --build
T='Authorization: Bearer local-dev-service-token'
curl -s -H "$T" localhost:8080/api/v1/workflows/wf001/versions
curl -s -X POST -d '{"label":"B"}' localhost:5678/mock/edit/wf001     # autosave: tanpa commit
curl -s -X POST localhost:5678/mock/publish/wf001                    # publish: commit dalam POLL_INTERVAL
```

Discovery API n8n yang asli (read-only, key dari env atau stdin, tidak dicetak): `scripts/discover.sh`.

## 15. Struktur repo

```
cmd/n8n-git-service/      main (wiring) + subcommand healthcheck
internal/config/          env → Config + validasi
internal/httpx/           middleware (request id, recover, access log, bearer, limit), logger JSON + redaksi
internal/n8n/             klien API publik n8n
internal/gitlab/          klien GitLab REST (files, commits, last_commit_id)
internal/workflow/        sanitasi, kanonikalisasi, __lines__, restore body, payload versi
internal/service/         publish, poller, versions, rollback, riwayat Git, handler /api/v1
internal/historyproxy/    proxy /rest/workflow-history untuk panel Versions n8n
internal/audit/           log audit
internal/metrics/         metrik Prometheus
api/openapi.yaml          kontrak API
deploy/local/             compose + mock n8n/GitLab
docs/                     discovery n8n 2.28.6
scripts/discover.sh       discovery read-only
Dockerfile, Jenkinsfile, .golangci.yml
```

## 16. Riwayat perubahan

| Tanggal | Commit / tag | Perubahan |
|---|---|---|
| 2026-10-20 | `2f8d23a` | Rilis awal: poller publish, sinkron ke GitLab, API versions/rollback, Jenkins/Docker/Helm. Deploy dev. |
| 2026-10-20 | `ad0cf86` | Nama workflow diambil dari objek workflow (endpoint versi n8n mengembalikan label "Version …"). |
| 2026-10-20 | `edddcf7` | Teks multi-baris disimpan per baris (`__lines__`) agar diff GitLab per baris. |
| 2026-10-20 | (values) | `POLL_INTERVAL` 30s → 10s. |
| 2026-10-20 | `073941b` = **`v0.1.0`** | Panel Versions n8n membaca GitLab (history proxy, mode merged), trailer `N8n-Version-Id`, `nodeGroups`, Ingress `/rest/workflow-history`. |
| 2026-10-20 | `71cbe3d` | Panel Versions **hanya commit GitLab** (`HISTORY_PROXY_MODE=git-only`, default). |
| 2026-10-20 | `9e839e3` | Mode `git-only`: draft saat ini ditampilkan paling atas bila berbeda dari published, agar Restore ke versi published tetap bisa. README lengkap (bahasa Indonesia). |
| 2026-10-20 | `e240e83` | Badge "(Published)" tetap pada commit HEAD setelah isi yang sama dipublish ulang (tanpa commit baru). |
| 2026-10-20 | `6ef5213` | Judul commit = `<nama workflow> (<id>)`; deskripsi Publish n8n masuk body commit + komentar commit GitLab; trailer `N8n-Version-Name`. |
| 2026-10-20 | `517ba13` = **`v2.0.0`** | Judul commit hanya nama workflow; id dipindah ke trailer `N8n-Workflow-Id`. |
| 2026-10-20 | `480d069` | `formatVersion: 2` di setiap file + deteksi commit "hanya format"; rollout memigrasi semua workflow published sekali (judul = nama workflow). |
| 2026-10-23 | `3d2528a` | Injeksi pengaturan OIDC enterprise di sharing-service (`/rest/settings`) sehingga tombol native "Sign in with SSO / OIDC" otomatis tampil di UI `/signin` n8n, serta dukungan dual login (SSO Keycloak & password lokal n8n). |
| 2026-10-23 | (auth-service) | Penambahan microservice ke-3: **`auth-service`** untuk OIDC Keycloak SSO (client `n8n-lab`, role `n8n-access`), JIT user auto-provisioning, dan fitur Account Takeover / Mapping akun lokal n8n lama (CLI `map-user` & API) tanpa kehilangan aset workflow/credentials. |
| 2026-10-26 | (auth-service) | Penambahan Endpoint REST API Manajemen: Enable/Disable status pengguna (`POST /admin/api/v1/users/{email}/status`), Delete pengguna (`DELETE /admin/api/v1/users/{email}`) dengan proteksi aset dan opsi `?force=true`, pencegahan overwrite status disabled pada login SSO, serta penolakan login SSO (HTTP 403 Forbidden) bila akun berstatus disabled. |
| 2026-10-26 | (auth-service) | Security hardening: Token-Based Identity (Bearer token via `ADMIN_API_TOKEN`), penonaktifan mutasi akun di exec pod CLI (Single Door of Entry), sinkronisasi otomatis role Admin Keycloak (group `n8n-admin` $\rightarrow$ `global:admin`, `n8n-user` $\rightarrow$ `global:member`), serta REST API `/admin/api/v1/transfer-ownership` & `/admin/api/v1/users`. |
| 2026-10-23 | (docs) | Panduan mapping akun SSO ke akun n8n lama (CLI `kubectl exec ... /app map-user`, Admin API, perilaku dua skenario) ditambahkan di §6.5. |
| 2026-10-23 | (sharing-service) | Granular workflow sharing via native UI modal n8n tanpa paywall lisensi (`sharing-service`, PUT `/rest/workflows/:id/share`). |
| 2026-10-22 | (git-sync) | Git trailers metadata `N8n-Workflow-Owner` dan `N8n-Workflow-Publisher` pada commit workflow. |
