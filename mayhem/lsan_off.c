/* Leaks are not the bug class this integration fuzzes for (SPEC §6.2 item 15). */
int __lsan_is_turned_off(void) { return 1; }
