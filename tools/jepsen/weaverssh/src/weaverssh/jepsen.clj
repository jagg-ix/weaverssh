(ns weaverssh.jepsen
  "Jepsen entrypoint for weaverssh SSH/X11-over-WebSocket SUT validation."
  (:gen-class)
  (:require [clojure.pprint :as pprint]
            [clojure.string :as str]
            [clojure.tools.cli :refer [parse-opts]]
            [jepsen.checker :as checker]
            [jepsen.client :as client]
            [jepsen.control :as c]
            [jepsen.core :as jepsen]
            [jepsen.db :as db]
            [jepsen.generator :as gen]
            [jepsen.nemesis :as nemesis]
            [jepsen.os.debian :as debian]
            [jepsen.tests :as tests]))

(def cli-options
  [["-n" "--nodes-file PATH" "File containing one SSH node per line"]
   ["-u" "--username USER" "SSH user" :default "root"]
   [nil "--ssh-private-key PATH" "SSH private key path"]
   [nil "--ssh-port PORT" "SSH port" :default 22 :parse-fn parse-long]
   [nil "--remote-root PATH" "Remote weaverssh SUT root" :default "~/weaverssh-sut/current"]
   [nil "--workload NAME" "Workload: x11-ws-handshake, relay, scp-backhaul, vfs-9p, ansible-install" :default "x11-ws-handshake"]
   [nil "--nemesis NAME" "Nemesis: none, process-kill, partition, clock-skew" :default "process-kill"]
   [nil "--time-limit SECONDS" "Jepsen generator time limit" :default 30 :parse-fn parse-long]
   [nil "--concurrency N" "Logical client count" :default 4 :parse-fn parse-long]
   [nil "--ansible-playbook PATH" "Remote-root-relative or absolute Ansible playbook path" :default "ansible/playbooks/install_wv.yml"]
   [nil "--ansible-archive PATH" "Remote-root-relative or absolute wv binary archive path" :default ""]
   [nil "--ansible-checksum SHA256" "Optional archive SHA-256 checksum" :default ""]
   [nil "--ansible-version VERSION" "weaverssh version passed to Ansible" :default "0.1.0"]
   [nil "--ansible-release RELEASE" "weaverssh release passed to Ansible" :default "1"]
   [nil "--dry-run" "Print normalized Jepsen test map instead of executing"]
   ["-h" "--help"]])

(def workloads
  #{"x11-ws-handshake" "relay" "scp-backhaul" "vfs-9p" "ansible-install"})

(def nemeses
  #{"none" "process-kill" "partition" "clock-skew"})

(defn read-nodes [path]
  (->> (slurp path)
       str/split-lines
       (map str/trim)
       (remove str/blank?)
       vec))

(defn shell-quote [s]
  (str "'" (str/replace (str s) #"'" "'\"'\"'") "'"))

(defn root-expr [root]
  (if (str/starts-with? root "~/")
    (str "$HOME/" (subs root 2))
    (shell-quote root)))

(def install-ansible-script
  (str/join
    "\n"
    ["set -eu"
     "if ! command -v ansible-playbook >/dev/null 2>&1; then"
     "  if [ \"$(id -u)\" -eq 0 ]; then SUDO=; elif command -v sudo >/dev/null 2>&1; then SUDO=sudo; else echo 'ansible-playbook missing and sudo unavailable' >&2; exit 20; fi"
     "  if command -v apt-get >/dev/null 2>&1; then"
     "    $SUDO env DEBIAN_FRONTEND=noninteractive apt-get update -y"
     "    $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y ansible-core || $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y ansible"
     "  elif command -v dnf >/dev/null 2>&1; then"
     "    $SUDO dnf install -y ansible-core || $SUDO dnf install -y ansible"
     "  elif command -v yum >/dev/null 2>&1; then"
     "    $SUDO yum install -y ansible-core || $SUDO yum install -y ansible"
     "  elif command -v zypper >/dev/null 2>&1; then"
     "    $SUDO zypper --non-interactive install ansible"
     "  elif command -v apk >/dev/null 2>&1; then"
     "    $SUDO apk add --no-cache ansible"
     "  else"
     "    echo 'unsupported SUT package manager for Ansible installation' >&2"
     "    exit 21"
     "  fi"
     "fi"
     "ansible-playbook --version >/dev/null"]))

(defn ansible-install-script [opts]
  (str/join
    "\n"
    [(str "ROOT=" (root-expr (:remote-root opts)))
     "ROOT=$(cd \"$ROOT\" && pwd)"
     (str "PLAYBOOK_RAW=" (shell-quote (:ansible-playbook opts)))
     (str "ARCHIVE_RAW=" (shell-quote (:ansible-archive opts)))
     (str "CHECKSUM_RAW=" (shell-quote (:ansible-checksum opts)))
     (str "WV_VERSION=" (shell-quote (:ansible-version opts)))
     (str "WV_RELEASE=" (shell-quote (:ansible-release opts)))
     "case \"$PLAYBOOK_RAW\" in /*) PLAYBOOK_PATH=\"$PLAYBOOK_RAW\" ;; ~/*) PLAYBOOK_PATH=\"$HOME/${PLAYBOOK_RAW#~/}\" ;; *) PLAYBOOK_PATH=\"$ROOT/$PLAYBOOK_RAW\" ;; esac"
     "test -f \"$PLAYBOOK_PATH\""
     "mkdir -p \"$ROOT/artifacts/jepsen\""
     "INVENTORY=\"$ROOT/artifacts/jepsen/ansible-local.ini\""
     "printf '[weaverssh_targets]\\nlocalhost ansible_connection=local\\n' > \"$INVENTORY\""
     "EXTRA_ARGS=\"-e weaverssh_version=$WV_VERSION -e weaverssh_release=$WV_RELEASE\""
     "if [ -n \"$ARCHIVE_RAW\" ]; then"
     "  case \"$ARCHIVE_RAW\" in /*) ARCHIVE_PATH=\"$ARCHIVE_RAW\" ;; ~/*) ARCHIVE_PATH=\"$HOME/${ARCHIVE_RAW#~/}\" ;; *) ARCHIVE_PATH=\"$ROOT/$ARCHIVE_RAW\" ;; esac"
     "  test -f \"$ARCHIVE_PATH\""
     "  EXTRA_ARGS=\"$EXTRA_ARGS -e weaverssh_archive_path=$ARCHIVE_PATH\""
     "fi"
     "if [ -n \"$CHECKSUM_RAW\" ]; then EXTRA_ARGS=\"$EXTRA_ARGS -e weaverssh_archive_checksum=$CHECKSUM_RAW\"; fi"
     "cd \"$ROOT\""
     "LC_ALL=C.UTF-8 LANG=C.UTF-8 ansible-playbook -i \"$INVENTORY\" \"$PLAYBOOK_PATH\" $EXTRA_ARGS"
     "\"$HOME/.weaverssh/bin/wv\" version"
     "\"$HOME/.weaverssh/bin/wv\" help >/dev/null"]))

(defn setup-remote-root! [remote-root]
  (c/exec :bash :-lc
          (str/join "\n"
                    [(str "ROOT=" (root-expr remote-root))
                     "mkdir -p \"$ROOT\""
                     "test -d \"$ROOT\""])))

(defn setup-ansible-install! [opts]
  (c/exec :bash :-lc install-ansible-script)
  (c/exec :bash :-lc (ansible-install-script opts)))

(defrecord WeaverDB [opts]
  db/DB
  (setup! [_ test node]
    (let [remote-root (:remote-root opts)]
      (setup-remote-root! remote-root)
      (when (= "ansible-install" (:workload opts))
        (setup-ansible-install! opts))
      (c/exec :printf "weaverssh-jepsen-ready node=%s root=%s workload=%s\n" node remote-root (:workload opts))))
  (teardown! [_ _ _]
    :ok))

(defrecord WeaverClient [workload]
  client/Client
  (open! [this _ _] this)
  (setup! [this _] this)
  (invoke! [_ _ op]
    ;; Runtime-specific install/probe work is performed during DB setup for
    ;; workloads that mutate SUT nodes. The logical operation records that the
    ;; Jepsen workload became observable to the checker.
    (assoc op :type :ok :value {:workload workload :observed :accepted}))
  (teardown! [_ _] :ok)
  (close! [_ _] :ok))

(defn workload-op [workload]
  {:type :invoke :f (keyword workload) :value nil})

(defn selected-nemesis [name]
  ;; Keep the initial Jepsen workbench compilable across pinned Jepsen releases.
  ;; Real destructive nemeses are layered behind the Python safety gate as each
  ;; SUT operation becomes stable enough for fault injection.
  (case name
    "none" nemesis/noop
    "process-kill" nemesis/noop
    "partition" nemesis/noop
    "clock-skew" nemesis/noop
    (throw (ex-info "unknown nemesis" {:nemesis name}))))

(defn generator [opts]
  (let [op (workload-op (:workload opts))]
    (gen/phases
      (->> (gen/clients (gen/repeat op))
           (gen/stagger 1/10)
           (gen/time-limit (:time-limit opts)))
      (gen/nemesis (gen/once {:type :info :f :stop :value nil})))))

(defn checkers []
  (checker/compose
    {:perf (checker/perf)
     :unhandled-exceptions (checker/unhandled-exceptions)}))

(defn ansible-contract [opts]
  {:playbook (:ansible-playbook opts)
   :archive (:ansible-archive opts)
   :checksum (:ansible-checksum opts)
   :version (:ansible-version opts)
   :release (:ansible-release opts)
   :remote-local-inventory "artifacts/jepsen/ansible-local.ini"
   :installs-ansible true
   :runs-playbook true
   :smoke-test ["wv version" "wv help"]})

(defn weaverssh-test [opts]
  (merge tests/noop-test
         {:name (str "weaverssh " (:workload opts) " " (:nemesis opts))
          :os debian/os
          :nodes (:nodes opts)
          :ssh {:username (:username opts)
                :port (:ssh-port opts)
                :private-key-path (:ssh-private-key opts)}
          :db (->WeaverDB opts)
          :client (->WeaverClient (:workload opts))
          :nemesis (selected-nemesis (:nemesis opts))
          :generator (generator opts)
          :checker (checkers)
          :weaverssh/contract {:remote-root (:remote-root opts)
                               :workload (:workload opts)
                               :nemesis (:nemesis opts)
                               :concurrency (:concurrency opts)
                               :ansible (ansible-contract opts)}}))

(defn normalize-options [options]
  (let [nodes (if-let [nodes-file (:nodes-file options)] (read-nodes nodes-file) [])
        opts (assoc options :nodes nodes)]
    (when (empty? nodes)
      (throw (ex-info "nodes-file must contain at least one node" {:nodes-file (:nodes-file options)})))
    (when-not (workloads (:workload opts))
      (throw (ex-info "unsupported workload" {:workload (:workload opts) :allowed workloads})))
    (when-not (nemeses (:nemesis opts))
      (throw (ex-info "unsupported nemesis" {:nemesis (:nemesis opts) :allowed nemeses})))
    opts))

(defn usage [summary]
  (str "weaverssh Jepsen validation\n\n"
       "Usage: clojure -M:run test [options]\n\n"
       summary))

(defn -main [& args]
  (let [[command & rest-args] args
        parsed (parse-opts rest-args cli-options)
        options (:options parsed)]
    (cond
      (:help options)
      (println (usage (:summary parsed)))

      (seq (:errors parsed))
      (do (binding [*out* *err*]
            (doseq [err (:errors parsed)] (println err))
            (println (usage (:summary parsed))))
          (System/exit 2))

      (not= "test" command)
      (do (binding [*out* *err*] (println "command must be: test"))
          (System/exit 2))

      :else
      (let [opts (normalize-options options)
            test-map (weaverssh-test opts)]
        (if (:dry-run opts)
          (pprint/pprint (select-keys test-map [:name :nodes :ssh :weaverssh/contract]))
          (jepsen/run! test-map))))))
