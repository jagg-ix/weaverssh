# Homebrew formula for weaverssh.
#
# Install via a tap:
#   brew tap jagg-ix/tap            # once the homebrew-tap repo exists
#   brew install weaverssh
#
# This formula builds the single `wv` binary from source. Once tagged releases
# are published, switch the `head`-style source for a `url`+`sha256` stanza
# pointing at the release tarball (see the commented block below).
class Weaverssh < Formula
  desc "User-space data bus over SSH: move files and sockets across locked-down infra"
  homepage "https://weaverssh.com"
  license "Apache-2.0"
  head "https://github.com/jagg-ix/weaverssh.git", branch: "main"

  # Released-tarball form (uncomment and fill in once v0.x.y is tagged):
  # url "https://github.com/jagg-ix/weaverssh/archive/refs/tags/v0.1.0.tar.gz"
  # sha256 "0000000000000000000000000000000000000000000000000000000000000000"

  depends_on "go" => :build

  def install
    system "go", "build", *std_go_args(output: bin/"wv"), "./cmd/wv"
    # `wv completion <shell>` prints the script for each shell.
    generate_completions_from_executable(bin/"wv", "completion", shells: [:bash, :zsh, :fish])
  end

  test do
    assert_match "weaverssh", shell_output("#{bin}/wv version")
    assert_match "Usage", shell_output("#{bin}/wv help")
  end
end
