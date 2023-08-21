const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});

    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "icmptunnel",
        .target = target,
        .optimize = optimize,
    });
    exe.addCSourceFiles(&.{
        "src/checksum.c",
        "src/client.c",
        "src/client-handlers.c",
        "src/daemon.c",
        "src/echo-skt.c",
        "src/forwarder.c",
        "src/icmptunnel.c",
        "src/privs.c",
        "src/resolve.c",
        "src/server.c",
        "src/server-handlers.c",
        "src/tun-device.c",
    }, &.{
        "-std=c99",
        "-pedantic",
        "-Wall",
        "-Wextra",
        "-fwhole-program",
        "-flto",
        "-Wno-int-conversion",
    });

    exe.addIncludePath(.{ .path = "src" });
    exe.linkLibC();
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);

    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
