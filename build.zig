const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const wave = b.addModule("wave", .{
        .root_source_file = b.path("source/wave.zig"),
        .target = target,
        .optimize = optimize,
    });

    const test_exe = b.addExecutable(.{
        .name = "test",
        .root_module = b.createModule(.{
            .root_source_file = b.path("test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "wave", .module = wave },
            },
        }),
    });
    b.installArtifact(test_exe);
}
