#!/usr/bin/env bash
# lfs.sh - Gerenciador de pacotes/receitas estilo LFS em Shell
# Licença: GPLv3
# Requisitos recomendados: bash, coreutils, tar, gzip, bzip2, xz, zstd, unzip, git, curl ou wget, patch, md5sum, findutils, fakeroot (opcional), file, sed, awk
set -euo pipefail
############################################
#                CONFIG                     #
############################################
REPO="${REPO:-/opt/lfspkgs}"                 # onde ficam as receitas: /$REPO/{base,x11,extras,desktop}
BINREPO_DIR="${BINREPO_DIR:-/opt/lfspkg-bin}"# onde guardar pacotes binários (.tar.zst)
WORKDIR="${WORKDIR:-/var/tmp/lfsbuild}"      # diretório de trabalho
PKGDB="${PKGDB:-/var/lib/lfspkg}"            # base de dados
LOGDIR="${LOGDIR:-/var/log/lfspkg}"          # logs por pacote
DESTDIR="${DESTDIR:-$WORKDIR/destdir}"       # destino de instalação temporária
GITREPO="${GITREPO:-}"                       # ex: /home/user/lfspkgs (repo git das receitas)
MIRROR_DIR="${MIRROR_DIR:-}"                 # diretório extra para sync (cópia)
DEFAULT_JOBS="${DEFAULT_JOBS:-$(nproc 2>/dev/null || echo 1)}"
STRIP_BY_DEFAULT="${STRIP_BY_DEFAULT:-0}"    # 1 para strip automático após instalar no DESTDIR
COLOR="${COLOR:-1}"                          # 0 desativa cores
SPINNER="${SPINNER:-1}"                      # 0 desativa spinner
PKGEXT="${PKGEXT:-tar.zst}"                  # extensão do pacote binário
# Estrutura do PKGDB
INSTDB="$PKGDB/db"                           # lista de pacotes instalados (metadados)
FILEDB="$PKGDB/files"                        # lista de arquivos por pacote
DEPSDB="$PKGDB/deps"                         # deps expandidas resolvidas
BACKUPDB="$PKGDB/backups"                    # backups de remoção/rollback
HOOKSDB="$PKGDB/hooks"                       # ganchos por pacote (ex: post_remove)

mkdir -p "$REPO"/{base,x11,extras,desktop} "$WORKDIR" "$DESTDIR" "$PKGDB" "$INSTDB" "$FILEDB" "$DEPSDB" "$BACKUPDB" "$HOOKSDB" "$BINREPO_DIR" "$LOGDIR"
# Verificação mínima de dependências
REQ_CMDS=(bash tar patch strip find xargs awk sed grep)
for cmd in "${REQ_CMDS[@]}"; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "[ERRO] Dependência obrigatória não encontrada: $cmd" >&2
    exit 1
  fi
done
############################################
#                UI/CORES                  #
############################################
if [[ "$COLOR" -eq 1 ]]; then
  C0="\033[0m"; C1="\033[1;34m"; C2="\033[1;32m"; C3="\033[1;33m"; C4="\033[1;31m"
else
  C0=""; C1=""; C2=""; C3=""; C4=""
fi
info(){ echo -e "${C1}[INFO]${C0} $*"; }
ok(){   echo -e "${C2}[ OK ]${C0} $*"; }
warn(){ echo -e "${C3}[WARN]${C0} $*"; }
err(){  echo -e "${C4}[ERRO]${C0} $*" >&2; }

spin_wrap(){ # executa comando em background com spinner
  if [[ "$SPINNER" -eq 0 ]]; then
    "$@"
    return
  fi
  local sp='-\|/' i=0
  "$@" & local pid=$!
  while kill -0 "$pid" 2>/dev/null; do
    i=$(( (i+1) % 4 ))
    printf "\r[%c] " "${sp:$i:1}"
    sleep 0.12
  done
  printf "\r"
  wait "$pid"
}
############################################
#           FUNÇÕES UTILITÁRIAS            #
############################################
have(){ command -v "$1" >/dev/null 2>&1; }

downloader(){
  if have curl; then
    curl -L --fail --retry 3 --connect-timeout 30 -o "$2" "$1"
  elif have wget; then
    wget -t 3 -T 30 -O "$2" "$1"
  else
    err "Nenhum downloader (curl/wget) encontrado."; exit 1
  fi
}

download(){
  local url="$1" out="$2"
  info "Baixando: $url"
  spin_wrap downloader "$url" "$out"
}

sha256_check(){
  local file="$1" expected="$2"
  [[ -z "${expected:-}" || "${expected,,}" == "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" ]] && { 
    warn "SHA256 não fornecido para $(basename "$file") — pulando verificação."; return; 
  }
  local got
  got=$(sha256sum "$file" | awk '{print $1}')
  if [[ "$got" != "$expected" ]]; then
    err "SHA256 divergente: esperado=$expected obtido=$got para $(basename "$file")"
    exit 1
  fi
  ok "SHA256 OK: $(basename "$file")"
}

extract(){
  local src="$1" dest="$2"
  mkdir -p "$dest"
  info "Extraindo $(basename "$src") em $dest"
  case "$src" in
    *.tar.gz|*.tgz)    tar -xzf "$src" -C "$dest" ;;
    *.tar.bz2)         tar -xjf "$src" -C "$dest" ;;
    *.tar.xz)          tar -xJf "$src" -C "$dest" ;;
    *.tar.zst)         tar --zstd -xpf "$src" -C "$dest" ;;
    *.tar)             tar -xf "$src" -C "$dest" ;;
    *.zip)             unzip -q "$src" -d "$dest" ;;
    *) err "Formato não suportado: $src"; exit 1 ;;
  esac
}

strip_destdir(){
  [[ "${STRIP_BY_DEFAULT}" -eq 0 && "${DO_STRIP:-0}" -eq 0 ]] && return 0
  if ! have strip; then warn "strip não encontrado — pulando."; return 0; fi
  info "Executando strip em binários no DESTDIR"
  find "$DESTDIR" -type f -exec sh -c '
    for f; do
      if file -b "$f" | grep -Eq "ELF .* (executable|shared object)"; then
        strip --strip-unneeded "$f" 2>/dev/null || true
      fi
    done
  ' sh {} +
}
# Log helpers
pkg_log(){
  local namever="$1" ; shift
  local logf="$LOGDIR/${namever}.log"
  "$@" 2>&1 | tee -a "$logf"
}
############################################
#           PARSER DE RECEITAS             #
############################################
# Formato: chave=[valor]
parse_recipe(){ # $1 = caminho da .lfpkg
  local rcp="$1"
  [[ -f "$rcp" ]] || { err "Receita não encontrada: $rcp"; exit 1; }

  # Apenas linhas no formato chave=[valor]
  while IFS="=" read -r key val; do
    [[ "$key" =~ ^[a-zA-Z0-9_]+$ ]] || continue
    val="${val#[}"
    val="${val%]}"
    eval "$key=\"\$val\""
  done < "$rcp"

  : "${deps:=}"
  : "${patchurl:=}"
  : "${patchsha256:=}"
  : "${pkgdir:=}"
  : "${preconfig:=}"
  : "${prepare:=}"
  : "${build:=}"
  : "${install:=}"
  : "${post_remove:=}"
  [[ -z "${JOBS:-}" ]] && JOBS="$DEFAULT_JOBS"
}

recipe_from_name(){ # encontra receita por nome (e opcional ver) no REPO
  local name="$1" ver="${2:-}"
  local found=""
  if [[ -n "$ver" ]]; then
    found=$(find "$REPO" -type f -name "${name}-${ver}.lfpkg" | head -n1 || true)
  fi
  if [[ -z "$found" ]]; then
    found=$(find "$REPO" -type f -name "${name}-*.lfpkg" | sort -V | tail -n1 || true)
  fi
  [[ -n "$found" ]] && echo "$found" && return 0
  err "Receita não localizada para $name ${ver:+(ver: $ver)}"
  exit 1
}

namever_from_recipe(){ # ecoa "pkgname-pkgver"
  local r="$1"
  parse_recipe "$r" >/dev/null 2>&1 || true
  echo "${pkgname}-${pkgver}"
}
############################################
#     GRAFO/RESOLUÇÃO DE DEPENDÊNCIAS      #
############################################
declare -A VISITED
declare -a ORDER

resolve_deps(){ # entrada: lista de nomes (ou caminhos .lfpkg). saída: ORDER (topo)
  VISITED=(); ORDER=()
  local items=("$@")
  for it in "${items[@]}"; do
    local rcp="$it"
    [[ "$rcp" == *.lfpkg ]] || rcp="$(recipe_from_name "$rcp")"
    dfs "$rcp"
  done
  printf "%s\n" "${ORDER[@]}"
}

dfs(){ # $1 receita
  local rcp="$1"
  local key
  key="$(realpath "$rcp")"
  [[ "${VISITED[$key]:-0}" -eq 2 ]] && return 0
  if [[ "${VISITED[$key]:-0}" -eq 1 ]]; then
    err "Ciclo de dependências detectado envolvendo $(namever_from_recipe "$rcp")"
    exit 1
  fi
  VISITED[$key]=1
  parse_recipe "$rcp"
  # deps é espaço-separado
  for d in $deps; do
    local drcp
    drcp="$(recipe_from_name "$d")"
    dfs "$drcp"
  done
  VISITED[$key]=2
  ORDER+=("$rcp")
}
############################################
#                 BUILD                    #
############################################
apply_patch_if_any(){ # usa patchurl/patchmd5
  local srcdir="$1"
  if [[ -n "${patchurl:-}" ]]; then
    local pfile="$WORKDIR/${patchurl##*/}"
    download "$patchurl" "$pfile"
    sha256_check "$srcfile" "${sha256sum:-}"
    info "Aplicando patch: $(basename "$pfile")"
    (cd "$srcdir" && patch -p1 < "$pfile")
  fi
}

do_build_only(){ # baixar+extrair+patch+compilar (NÃO instalar)
  local rcp="$1"; parse_recipe "$rcp"
  local namever="${pkgname}-${pkgver}"
  local srcfile="$WORKDIR/${pkgurl##*/}"
  local logid="${namever}"
  mkdir -p "$WORKDIR/src" "$WORKDIR/builds"
  # download src
  if [[ ! -f "$srcfile" ]]; then
    download "$pkgurl" "$srcfile"
  fi
  sha256_check "$srcfile" "${sha256sum:-}"
  # extrair
  rm -rf "$WORKDIR/src/$namever"
  extract "$srcfile" "$WORKDIR/src"
  # detectar diretório (alguns tarballs criam $pkgname-$pkgver)
  local srcdir
  srcdir="$(find "$WORKDIR/src" -maxdepth 1 -type d -name "${pkgname}*" | head -n1)"
  [[ -d "$srcdir" ]] || { err "Diretório de fonte não encontrado após extração."; exit 1; }
  # patch
  apply_patch_if_any "$srcdir"
  # hooks
  pushd "$srcdir" >/dev/null
  [[ -n "$preconfig" ]] && info "preconfig…" && pkg_log "$logid" bash -lc "$preconfig"
  [[ -n "$prepare"   ]] && info "prepare…"   && pkg_log "$logid" bash -lc "$prepare"
  # export de variáveis úteis
  export DESTDIR JOBS
  if [[ -z "$build" ]]; then
    warn "Hook 'build' vazio — tentando compilar com 'make -j$JOBS' por padrão."
    pkg_log "$logid" make -j"$JOBS"
  else
    info "build…"
    pkg_log "$logid" bash -lc "$build"
  fi
  popd >/dev/null
  ok "Build concluído (sem instalar): $namever"
}

do_install_from_build(){ # instala (make install) em DESTDIR (com fakeroot opcional), empacota, e NÃO move p/ root (a não ser subcomando install-bin)
  local rcp="$1"; parse_recipe "$rcp"
  local namever="${pkgname}-${pkgver}"
  local srcdir
  srcdir="$(find "$WORKDIR/src" -maxdepth 1 -type d -name "${pkgname}*" | head -n1)"
  [[ -d "$srcdir" ]] || { err "Fonte não preparada. Rode: $0 build $rcp"; exit 1; }

  rm -rf "$DESTDIR"
  mkdir -p "$DESTDIR"

  export DESTDIR JOBS
  info "Executando hook install no DESTDIR"
  if [[ -z "$install" ]]; then
    err "Hook 'install' não definido na receita."; exit 1
  fi

  if have fakeroot; then
    pkg_log "$namever" fakeroot -- bash -lc "$(
      printf 'cd %q && %s' "$srcdir" "$install"
    )"
  else
    warn "fakeroot não disponível — tentando instalar sem ele no DESTDIR."
    pkg_log "$namever" bash -lc "cd \"$srcdir\" && $install"
  fi

  # strip opcional
  strip_destdir

  # gerar lista de arquivos
  local flist="$WORKDIR/${namever}.filelist"
  (cd "$DESTDIR" && find . -type f -o -type l -o -type d | sed 's#^\./#/#') | sort > "$flist"

  # empacotar
  mkdir -p "$BINREPO_DIR"
  local pkgfile="$BINREPO_DIR/${namever}.${PKGEXT}"
  info "Empacotando: $(basename "$pkgfile")"
  case "$PKGEXT" in
    tar.zst) (cd "$DESTDIR" && tar --zstd -cpf "$pkgfile" .) ;;
    tar.xz)  (cd "$DESTDIR" && tar -Jcpf "$pkgfile" .) ;;
    tar.gz)  (cd "$DESTDIR" && tar -zcpf "$pkgfile" .) ;;
    *) err "PKGEXT não suportado: $PKGEXT"; exit 1 ;;
  esac

  # salvar metadados/registro (ainda não 'instalado' no sistema)
  echo "name=$pkgname"   > "$INSTDB/${namever}"
  echo "ver=$pkgver"    >> "$INSTDB/${namever}"
  echo "recipe=$(realpath "$rcp")" >> "$INSTDB/${namever}"
  echo "built=$(date -u +%FT%TZ)" >> "$INSTDB/${namever}"
  echo "pkgfile=$pkgfile"        >> "$INSTDB/${namever}"
  echo "$deps" > "$DEPSDB/${namever}"
  cp "$flist" "$FILEDB/${namever}"
  [[ -n "${post_remove:-}" ]] && printf "%s\n" "$post_remove" > "$HOOKSDB/${namever}"

  ok "Pacote binário criado: $pkgfile"
  info "Para instalar no sistema: $0 install-bin ${pkgname} ${pkgver}"
}

############################################
#        INSTALAÇÃO DO PACOTE BINÁRIO      #
############################################
install_bin(){ # instala pacote do BINREPO para /
  local name="${1:?nome}" ver="${2:-}"
  local rcp
  rcp="$(recipe_from_name "$name" "${ver:-}")"
  parse_recipe "$rcp"
  local namever="${pkgname}-${pkgver}"
  local meta="$INSTDB/${namever}"
  local pkgfile
  if [[ -f "$meta" ]]; then
    pkgfile="$(grep '^pkgfile=' "$meta" | cut -d= -f2-)"
    [[ -f "$pkgfile" ]] || pkgfile="$BINREPO_DIR/${namever}.${PKGEXT}"
  else
    pkgfile="$BINREPO_DIR/${namever}.${PKGEXT}"
  fi
  [[ -f "$pkgfile" ]] || { err "Pacote binário não encontrado: $pkgfile"; exit 1; }
  # checar conflitos de arquivos
  while read -r f; do
    if [[ -e "/$f" ]]; then
      for other in "$FILEDB"/*; do
        grep -qx "/$f" "$other" 2>/dev/null && {
          warn "Conflito: $f já pertence a $(basename "$other")"
        }
      done
    fi
  done < <(tar -tf "$pkgfile")

  info "Instalando binário no / (necessita permissões adequadas)"
  # backup para rollback
  local bdir="$BACKUPDB/${namever}.$(date +%s)"
  mkdir -p "$bdir"
  # extrair e registrar
  tar -tf "$pkgfile" | sed 's#^#/#' | sort > "$bdir/new-files.list"
  # sobrepor no sistema
  (cd / && tar -xpf "$pkgfile")
  # registrar como instalado
  echo "installed=$(date -u +%FT%TZ)" >> "$INSTDB/${namever}"
  cp "$bdir/new-files.list" "$FILEDB/${namever}"
  ok "Instalado: $namever"
}

############################################
#        INSTALAÇÃO A PARTIR DO WORKDIR    #
############################################
install_from_work(){ # usa arquivos já em $DESTDIR (sem repacotar), instala em /
  local rcp="$1"; parse_recipe "$rcp"
  local namever="${pkgname}-${pkgver}"
  [[ -d "$DESTDIR" ]] || { err "DESTDIR inexistente. Rode: $0 build $rcp && $0 install-stage $rcp"; exit 1; }
  info "Instalando do DESTDIR para /"
  (cd "$DESTDIR" && tar -cpf - .) | (cd / && tar -xpf -)
  # registrar arquivos
  (cd "$DESTDIR" && find . -type f -o -type l -o -type d | sed 's#^\./#/#' | sort) > "$FILEDB/${namever}"
  echo "installed=$(date -u +%FT%TZ)" >> "$INSTDB/${namever}"
  ok "Instalado: $namever"
}

############################################
#            REMOÇÃO / ROLLBACK            #
############################################
remove_pkg(){ # remove arquivos listados e roda hook post_remove
  local name="$1" ver="${2:-}"
  local rcp
  rcp="$(recipe_from_name "$name" "${ver:-}")"
  parse_recipe "$rcp"
  local namever="${pkgname}-${pkgver}"
  local flist="$FILEDB/${namever}"
  [[ -f "$flist" ]] || { err "Lista de arquivos não encontrada para $namever"; exit 1; }

  info "Removendo $namever"
  local rmbak="$BACKUPDB/${namever}.rm.$(date +%s)"
  mkdir -p "$rmbak"
  # mover arquivos para backup (para desfazer)
  while IFS= read -r f; do
    if [[ -e "$f" || -L "$f" ]]; then
      mkdir -p "$rmbak/$(dirname "$f")"
      # tenta copiar preservando metadata; se diretório, só registra
      if [[ -f "$f" || -L "$f" ]]; then
        cp -a --parents "$f" "$rmbak" 2>/dev/null || true
      fi
      rm -rf "$f"
    fi
  done < "$flist"

  # hook pós-remover
  local hk="$HOOKSDB/${namever}"
  if [[ -s "$hk" ]]; then
    info "Executando hook pós-remover"
    bash -lc "$(cat "$hk")" || warn "hook pós-remover retornou erro (ignorado)."
  fi

  # limpar registros
  rm -f "$INSTDB/${namever}" "$FILEDB/${namever}" "$DEPSDB/${namever}" "$HOOKSDB/${namever}"
  ok "Removido: $namever"
  info "Para desfazer: $0 undo-remove ${pkgname} ${pkgver} \"$rmbak\""
}

undo_remove(){ # restaura backup de uma remoção
  local name="$1" ver="$2" bakdir="${3:?backup_dir}"
  parse_recipe "$(recipe_from_name "$name" "$ver")"
  info "Restaurando a partir de $bakdir"
  (cd "$bakdir" && find . -type d -o -type f -o -type l | sed 's#^\./##') | while read -r rel; do
    mkdir -p "/$(dirname "$rel")"
    cp -a "$bakdir/$rel" "/$rel"
  done
  ok "Restauração concluída."
}
############################################
#           BUSCA / INFO / LOGS            #
############################################
search_pkg(){ # busca por nome nos diretórios do REPO
  local q="${1:?termo}"
  find "$REPO" -type f -name "*.lfpkg" -path "*/$q-*.lfpkg" -print
}

pkg_info(){
  local rcp; rcp="$( [[ -f "${1:-}" ]] && echo "$1" || recipe_from_name "$1" "${2:-}" )"
  parse_recipe "$rcp"
  local namever="${pkgname}-${pkgver}"
  echo "Pacote : $pkgname"
  echo "Versão : $pkgver"
  echo "DirRec : ${pkgdir:-}"
  echo "URL    : $pkgurl"
  echo "MD5    : ${md5sum:-<não definido>}"
  echo "Patch  : ${patchurl:-<nenhum>}"
  echo "Deps   : ${deps:-<nenhuma>}"
  echo "Log    : $LOGDIR/${namever}.log"
  echo "Bin    : $BINREPO_DIR/${namever}.${PKGEXT}"
  [[ -f "$INSTDB/${namever}" ]] && echo "Status : BUILT$(grep -q '^installed=' "$INSTDB/${namever}" && echo ', INSTALLED')"
}

############################################
#           SYNC (git e diretório)         #
############################################
sync_all(){
  if [[ -n "$GITREPO" && -d "$GITREPO/.git" ]]; then
    info "Sincronizando repo git: $GITREPO"
    (cd "$GITREPO" && git add -A && git commit -m "lfspkg sync $(date -u +%FT%TZ)" || true && git push || true)
  fi
  if [[ -n "$MIRROR_DIR" ]]; then
    info "Espelhando $REPO -> $MIRROR_DIR"
    rsync -a --delete "$REPO/" "$MIRROR_DIR/"
  fi
  ok "Sync concluído."
}

############################################
#       RECOMPILAR (SISTEMA/UM PKG)        #
############################################
rebuild_all(){
  info "Recompilando todo o sistema respeitando dependências…"
  local all
  mapfile -t all < <(find "$REPO" -type f -name "*.lfpkg" | sort)
  mapfile -t topo < <(resolve_deps "${all[@]}")
  for r in "${topo[@]}"; do
    info "==> $r"
    build_flow "$r" # full flow (build-only + install-stage + package), mas não instala no /
  done
  ok "Rebuild completo."
}

rebuild_one(){
  local name="$1"
  local rcp; rcp="$(recipe_from_name "$name" "${2:-}")"
  mapfile -t topo < <(resolve_deps "$rcp")
  for r in "${topo[@]}"; do
    build_flow "$r"
  done
  ok "Rebuild de $name concluído."
}

############################################
#     FLUXOS (build, instalar, empacotar)  #
############################################
build_flow(){ # respeita --force/--strip
  local rcp="$1"; parse_recipe "$rcp"
  local namever="${pkgname}-${pkgver}"
  if [[ -z "${FORCE:-}" && -f "$INSTDB/${namever}" && -f "$BINREPO_DIR/${namever}.${PKGEXT}" ]]; then
    info "Pulando (já construído): $namever — use --force para reconstruir."
    return 0
  fi
  do_build_only "$rcp"
  do_install_from_build "$rcp"   # instala em DESTDIR, faz pacote binário e registra (não instala no /)
}

############################################
#       CRIAR ESQUELETO DE RECEITA         #
############################################
new_recipe(){
  local cat="$1" name="$2" ver="$3"
  [[ -z "$cat" || -z "$name" || -z "$ver" ]] && { err "Uso: new <base|x11|extras|desktop> <nome> <versão>"; exit 1; }
  local dir="$REPO/$cat/${name}-${ver}"
  mkdir -p "$dir"
  local rcp="$dir/${name}-${ver}.lfpkg"
  cat > "$rcp" <<EOF
pkgdir=[${name}-${ver}-1]
pkgname=[${name}]
pkgver=[${ver}]
pkgurl=[http://example.org/${name}-${ver}.tar.xz]
md5sum=[xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx]
patchurl=[]
patchmd5=[]
deps=[]

# hooks
preconfig=[]
prepare=[./configure --prefix=/usr]
build=[make -j\$(nproc)]
install=[make DESTDIR=\$DESTDIR install]
# hooks opcionais de remoção
post_remove=[]
EOF
  ok "Criado: $rcp"
  echo "$rcp"
}

############################################
#                USO/HELP                  #
############################################
usage(){
  cat <<'EOF'
Uso: lfs.sh <comando> [opções] [alvos]

Comandos principais:
  resolve <receita|nome>             Resolve deps e imprime ordem topológica
  build <receita|nome>               Baixa/extrai/aplica patch/compila (NÃO instala)
  install-stage <receita|nome>       Instala no DESTDIR, aplica strip (opcional) e empacota (NÃO instala no /)
  build-package <receita|nome>       Atalho: build + install-stage
  install-bin <nome> [versão]        Instala pacote binário do BINREPO em /
  install-from-work <receita>        Instala do DESTDIR atual em /
  remove <nome> [versão]             Remove arquivos e executa hook pós-remover
  undo-remove <nome> <versão> <bak>  Desfaz última remoção usando backup
  info <receita|nome> [versão]       Mostra info da receita/pacote
  search <termo>                     Procura receitas por nome
  clean                               Limpa WORKDIR/DESTDIR
  sync                                Commit/push no GITREPO e rsync MIRROR_DIR
  rebuild-all                        Recompila todas as receitas (topológico)
  rebuild <nome> [versão]            Recompila um pacote e seus deps
  new <categoria> <nome> <versão>    Cria esqueleto de receita

Opções (antes do comando):
  --force          Força reconstrução mesmo se já houver pacote
  --strip          Força strip no DESTDIR
  --no-color       Desativa cores
  --no-spinner     Desativa spinner

Exemplos:
  REPO=/repo LFS ./lfs.sh build $REPO/base/glibc-2.41/glibc-2.41.lfpkg
  ./lfs.sh build gcc
  ./lfs.sh install-stage glibc
  ./lfs.sh install-bin glibc 2.41
  ./lfs.sh remove glibc 2.41
  ./lfs.sh rebuild-all
  ./lfs.sh new base zlib 1.3.1
EOF
}

############################################
#                CLI/PARSE                 #
############################################
FORCE=""
DO_STRIP=0
ARGS=()
while (($#)); do
  case "${1:-}" in
    --force) FORCE=1; shift;;
    --strip) DO_STRIP=1; shift;;
    --no-color) COLOR=0; shift;;
    --no-spinner) SPINNER=0; shift;;
    -h|--help) usage; exit 0;;
    *) ARGS+=("$1"); shift;;
  esac
done
set -- "${ARGS[@]:-}"

cmd="${1:-}"; shift || true

case "${cmd:-}" in
  resolve)
    mapfile -t topo < <(resolve_deps "$@")
    printf "%s\n" "${topo[@]}"
    ;;
  build)
    rcp="$( [[ -f "${1:-}" ]] && echo "$1" || recipe_from_name "${1:?alvo}" "${2:-}" )"
    do_build_only "$rcp"
    ;;
  install-stage|stage|package)
    rcp="$( [[ -f "${1:-}" ]] && echo "$1" || recipe_from_name "${1:?alvo}" "${2:-}" )"
    do_install_from_build "$rcp"
    ;;
  build-package)
    rcp="$( [[ -f "${1:-}" ]] && echo "$1" || recipe_from_name "${1:?alvo}" "${2:-}" )"
    build_flow "$rcp"
    ;;
  install-bin)
    install_bin "${1:?nome}" "${2:-}"
    ;;
  install-from-work)
    rcp="$( [[ -f "${1:-}" ]] && echo "$1" || recipe_from_name "${1:?alvo}" "${2:-}" )"
    install_from_work "$rcp"
    ;;
  remove)
    remove_pkg "${1:?nome}" "${2:-}"
    ;;
  undo-remove)
    undo_remove "${1:?nome}" "${2:?ver}" "${3:?backup_dir}"
    ;;
  info)
    pkg_info "${1:?alvo}" "${2:-}"
    ;;
  search)
    search_pkg "${1:?termo}"
    ;;
  clean)
    info "Limpando diretórios de trabalho…"
    rm -rf "$WORKDIR"/* "$DESTDIR"/*
    ok "OK"
    ;;
  sync)
    sync_all
    ;;
  rebuild-all)
    rebuild_all
    ;;
  rebuild)
    rebuild_one "${1:?nome}" "${2:-}"
    ;;
  new)
    new_recipe "${1:?cat}" "${2:?nome}" "${3:?ver}"
    ;;
  ""|-h|--help)
    usage
    ;;
  *)
    err "Comando desconhecido: $cmd"; usage; exit 1;;
esac
