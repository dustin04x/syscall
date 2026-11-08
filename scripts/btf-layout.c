// SPDX-License-Identifier: MIT
//
// Verify the tracepoint context layouts used by ebpf/syscall.bpf.c against the
// running kernel's BTF. This helper is read-only and does not require root on
// kernels that expose /sys/kernel/btf/vmlinux as readable.
//
// Build and run with scripts/check-btf-layout.sh.

#include <bpf/btf.h>
#include <linux/btf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct member_expectation {
    const char *name;
    unsigned int bit_offset;
};

struct struct_expectation {
    const char *name;
    unsigned int size;
    unsigned int member_count;
    struct member_expectation members[8];
};

static const struct struct_expectation EXPECTATIONS[] = {
    {
        .name = "trace_event_raw_sched_process_exec",
        .size = 20,
        .member_count = 4,
        .members = {
            {"ent", 0},
            {"__data_loc_filename", 64},
            {"pid", 96},
            {"old_pid", 128},
        },
    },
    {
        .name = "trace_event_raw_sched_process_fork",
        .size = 48,
        .member_count = 5,
        .members = {
            {"ent", 0},
            {"parent_comm", 64},
            {"parent_pid", 192},
            {"child_comm", 224},
            {"child_pid", 352},
        },
    },
    {
        .name = "trace_event_raw_sched_process_template",
        .size = 32,
        .member_count = 4,
        .members = {
            {"ent", 0},
            {"comm", 64},
            {"pid", 192},
            {"prio", 224},
        },
    },
};

static const struct btf_member *find_member(const struct btf *btf,
                                             const struct btf_type *type,
                                             const char *name)
{
    unsigned int i;

    for (i = 0; i < btf_vlen(type); i++) {
        const struct btf_member *member = btf_members(type) + i;
        const char *member_name = btf__name_by_offset(btf, member->name_off);

        if (member_name && strcmp(member_name, name) == 0)
            return member;
    }
    return NULL;
}

int main(int argc, char **argv)
{
    const char *path = argc > 1 ? argv[1] : "/sys/kernel/btf/vmlinux";
    struct btf *btf;
    int failures = 0;
    size_t i;

    btf = btf__parse(path, NULL);
    if (!btf) {
        fprintf(stderr, "FAIL: could not parse BTF at %s\n", path);
        return 1;
    }

    for (i = 0; i < sizeof(EXPECTATIONS) / sizeof(EXPECTATIONS[0]); i++) {
        const struct struct_expectation *expectation = &EXPECTATIONS[i];
        int id = btf__find_by_name_kind(btf, expectation->name, BTF_KIND_STRUCT);
        const struct btf_type *type;
        unsigned int j;
        int struct_failures = 0;

        if (id < 0) {
            printf("FAIL %-46s missing struct\n", expectation->name);
            failures++;
            continue;
        }
        type = btf__type_by_id(btf, (unsigned int)id);
        if (!type) {
            printf("FAIL %-46s type lookup failed\n", expectation->name);
            failures++;
            continue;
        }
        if (type->size != expectation->size) {
            printf("FAIL %-46s size %u, expected %u\n",
                   expectation->name, type->size, expectation->size);
            failures++;
            continue;
        }

        for (j = 0; j < expectation->member_count; j++) {
            const struct member_expectation *member_expect = &expectation->members[j];
            const struct btf_member *member =
                find_member(btf, type, member_expect->name);

            if (!member) {
                printf("FAIL %-46s missing member %s\n",
                       expectation->name, member_expect->name);
                struct_failures++;
                continue;
            }
            if (member->offset != member_expect->bit_offset) {
                printf("FAIL %-46s member %s at bit %u, expected %u\n",
                       expectation->name, member_expect->name,
                       member->offset, member_expect->bit_offset);
                struct_failures++;
            }
        }

        failures += struct_failures;
        if (struct_failures == 0)
            printf("PASS %-46s size=%u members verified\n",
                   expectation->name, type->size);
    }

    btf__free(btf);
    if (failures != 0) {
        printf("\n%d BTF layout check(s) failed.\n", failures);
        return 1;
    }
    printf("\nAll tracepoint context layouts match the running kernel BTF.\n");
    return 0;
}
