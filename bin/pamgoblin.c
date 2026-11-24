
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int converse(int count, const struct pam_message **messages,
                    struct pam_response **responses, void *data)
{
    struct pam_response *reply = calloc(count, sizeof(*reply));
    if (!reply)
        return PAM_BUF_ERR;

    for (int i = 0; i < count; i++) {
        switch (messages[i]->msg_style) {
        case PAM_TEXT_INFO:
        case PAM_ERROR_MSG:
            puts(messages[i]->msg);
            break;
        default:
            free(reply);
            return PAM_CONV_ERR;
        }
    }

    *responses = reply;
    return PAM_SUCCESS;
}

int main(void)
{
    struct pam_conv conversation = { converse, NULL };
    pam_handle_t *pamh = NULL;

    const char *user = getlogin();
    if (!user) {
        fprintf(stderr, "Cannot determine login user\n");
        return 1;
    }

    int result = pam_start("pam-goblin", user, &conversation, &pamh);

    if (result == PAM_SUCCESS)
        result = pam_authenticate(pamh, 0);  // No PAM_SILENT

    printf("PAM result: %s\n", pam_strerror(pamh, result));

    if (pamh)
        pam_end(pamh, result);

    return result == PAM_SUCCESS ? 0 : 1;
}

