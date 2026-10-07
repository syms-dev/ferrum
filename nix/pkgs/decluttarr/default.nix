# Decluttarr, packaged from its GitHub source.
#
# WHY FROM SOURCE RATHER THAN FROM nixpkgs OR A CONTAINER.
#
# It is not in ferrum's pinned nixpkgs -- confirmed against this repo's own
# flake.lock revision: `builtins.hasAttr "decluttarr" pkgs` is false. Upstream
# publishes no PyPI distribution either; the two shipping forms are "clone the
# repo and run `python3 main.py`" and a container image.
#
# The container is deliberately not taken. ferrum has no OCI runtime anywhere
# in its module tree, and introducing one for a single app would put a layer
# ferrum cannot evaluate between the operator and a process that DELETES THEIR
# DOWNLOADS. The whole closure guarantee -- every byte of a ferrum host is
# reachable from this flake and its lock -- would hold for six apps and not
# the seventh.
#
# So the build is the upstream repository, verbatim, plus an interpreter from
# the pinned nixpkgs carrying exactly the imports the source actually makes.
#
# DEPENDENCIES. Taken from the real top-level imports under src/ and main.py,
# NOT from docker/requirements.txt: that file is the project's development
# environment and lists pytest, black, pylint, ruff, pre-commit, isort,
# autoflake and demjson3, none of which the running program imports. It also
# lists `asyncio`, which on PyPI is a dead 3.4-era backport that would shadow
# the standard library module `main.py` actually uses.
#
# The six below are the complete set, each present in the pinned nixpkgs:
#   requests          src/utils/common.py, src/settings/_download_clients_qbit.py
#   packaging         src/settings/_download_clients_qbit.py (version compare)
#   watchdog          src/deletion_handler/deletion_handler.py
#   pyyaml            src/settings/_user_config.py
#   pyyaml-env-tag    src/settings/_user_config.py (`from yaml_env_tag import ...`)
#   python-dateutil   src/utils/queue_manager.py
#
# A seventh import would fail at `import` time inside the unit rather than at
# build time, because nothing here type-checks the source. The compile pass in
# installPhase is the cheap partial guard: it catches syntax that this
# interpreter cannot parse at BUILD time, which is the failure a Python
# version bump actually produces.
{ lib
, stdenvNoCC
, fetchFromGitHub
, python3
, makeWrapper
}:

let
  pythonEnv = python3.withPackages (ps: [
    ps.requests
    ps.packaging
    ps.watchdog
    ps.pyyaml
    ps.pyyaml-env-tag
    ps.python-dateutil
  ]);
in
stdenvNoCC.mkDerivation (finalAttrs: {
  pname = "decluttarr";
  version = "2.2.0";

  src = fetchFromGitHub {
    owner = "ManiMatter";
    repo = "decluttarr";
    rev = "v${finalAttrs.version}";
    hash = "sha256-36XOEnNE5aJg9QkVK2nI8xK3RiugNH3Xjhswt3dhj+s=";
  };

  nativeBuildInputs = [ makeWrapper ];

  dontConfigure = true;
  dontBuild = true;

  # main.py does `from src.job_manager import JobManager`, so the directory
  # holding BOTH main.py and src/ has to be on sys.path. Invoking the script
  # by its absolute path is what puts it there: CPython sets sys.path[0] to
  # the script's own directory, which is why this wrapper does not need to
  # set PYTHONPATH and why the unit is free to chdir anywhere it likes --
  # and it must, since upstream resolves ./config/config.yaml and
  # ./logs/logs.txt relative to the working directory (src/settings/
  # _constants.py's `Paths`).
  installPhase = ''
    runHook preInstall

    mkdir -p $out/libexec/decluttarr
    cp main.py $out/libexec/decluttarr/main.py
    cp -r src $out/libexec/decluttarr/src

    # Parses every installed module with THIS interpreter. Upstream's own
    # Dockerfile pins python 3.10 and the pinned nixpkgs offers ${python3.version},
    # so "does the source still parse" is a real question with a cheap
    # mechanical answer, and the answer belongs at build time rather than in
    # a unit that fails to start on a host.
    ${pythonEnv}/bin/python -m compileall -q $out/libexec/decluttarr

    makeWrapper ${pythonEnv}/bin/python $out/bin/decluttarr \
      --add-flags $out/libexec/decluttarr/main.py \
      --set PYTHONUNBUFFERED 1 \
      --set PYTHONDONTWRITEBYTECODE 1

    runHook postInstall
  '';

  meta = {
    description = "Cleans stalled and broken downloads out of Sonarr/Radarr queues";
    homepage = "https://github.com/ManiMatter/decluttarr";
    license = lib.licenses.gpl3Only;
    mainProgram = "decluttarr";
    platforms = lib.platforms.linux;
  };
})
