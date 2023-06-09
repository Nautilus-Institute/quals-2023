#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#define INPUT_SIZE 512
#define ALARM_SECONDS 180

struct __attribute__((packed)) item  {
    char buf[INPUT_SIZE];
    struct item* next;
    struct item* prev;
};

static struct item head;        // Head of our global linked list
static bool reviewed = false;   // Flag for whether user left a review or not
static int totalReviews = 0;

void alarm_handler(int signal){
    (void)signal;

    char *bye = "I'm sorry, the open house is closing now. Bye!\n";
    write(1, bye, strlen(bye));
    exit(1);
}

void new(char *msg)
{
    struct item *ptr;
    unsigned int len;

    // Seek through our linked list to find the tail
    for (ptr = &head; ptr->next; ptr = ptr->next);

    // Create a new entry and link it to the list
    ptr->next = malloc(sizeof(struct item));
    ptr->next->prev = ptr;
    ptr = ptr->next;

    ptr->next = 0;  // new entry is now the tail

    totalReviews++; 

    // Copy message into the buffer
    len = (strlen(msg) > 512) ? 512 : strlen(msg);
    strncpy(ptr->buf, msg, len);
    // Intentionally missing a NULL-terminator here to create a pointer leak

    // fprintf(stderr, "NewNode = %p %p\n", &ptr->next, ptr);

    return;
}


void create()
{
    char input[INPUT_SIZE*2];

    // Receive review from user
    fputs("Absolutely, we'd love to have your review!\n", stdout);
    if (fgets(input, INPUT_SIZE*2, stdin) == NULL) {
        return;
    }

    // If we received a review, place it at the end of the list
    if (strlen(input) > 0) {
        new(input);
        fputs("Thanks!\n", stdout);
    } else {
        fputs("I know. I'm speechless, too! It really is a great property.\n", stdout);
    }

    return;
}


void view()
{
    struct item *ptr;
    int numReviews = 0;
    if (head.next) {
        fputs("Check out these recent rave reviews from other prospective homebuyers:\n", stdout);
    // fprintf(stderr, "TR = %08x HeadPtr.next = %p HeadPtr.prev = %p Rev = %d\n", totalReviews, head.next, head.prev, reviewed);

        for (ptr = head.next; (numReviews++ < totalReviews) && ptr; ptr = ptr->next) {
    //          fprintf(stderr, "Iter = %d Total = %d Ptr = %p PB = %p\n", numReviews, totalReviews, ptr, ptr->buf);
            fprintf(stdout, "**** - %s\n", ptr->buf);
        }
    } else {
        fputs("Wait, where did all of the reviews go?!\n", stdout);
    }
    return;
}


void modify()
{
    struct item *ptr = &head;
    char buf[INPUT_SIZE+16];
    unsigned long selection;

    // Ask user for their selection
    fputs("Which of these reviews should we replace?\n", stdout);
    if (fgets(buf, INPUT_SIZE+16, stdin) == NULL) {
        return;
    }

    // Advance ptr to their selection
    selection = strtoul(buf, NULL, 10);
    for (unsigned int i = 0; i != selection; i++) {
        ptr = (ptr->next) ? ptr->next : ptr;
        if(ptr->next == NULL)
        {
            break;
        }
    }

    //  fprintf(stderr, "MOD PTR = %p Head = %p %d\n", ptr, &head, &head == ptr);
    // Replace their selection with their input
    fprintf(stdout, "Replacing this one: %s\n", ptr->buf);
    fputs("What do you think we should we replace it with?\n", stdout);
    if (fgets(ptr->buf, INPUT_SIZE+16, stdin) == NULL) {
        return;
    }

   //  fprintf(stderr, "MOD FIN head.next = %p head.prev = %p tot = %d rev = %d\n", head.next, head.prev, totalReviews, reviewed);

    return;
}

void delete()
{
    struct item *ptr = &head;
    char buf[16];
    unsigned long selection;

    // Ask user for their selection
    fputs("Which of these reviews should we delete?\n", stdout);
    if (fgets(buf, 16, stdin) == NULL) {
        return;
    }

    // Advance ptr to their selection
    selection = strtoul(buf, NULL, 10);
    for (unsigned int i = 0; i != selection; i++) {
        ptr = (ptr->next) ? ptr->next : ptr;
        if(ptr->next == NULL)
        {
            break;
        }
    }

    if(ptr == &head)
    {
        fputs("Can't delete that one\n", stdout);
        return;
    }
    
    fprintf(stdout, "Deleted entry: %s\n", ptr->buf);
    ptr->prev->next = ptr->next;
    if(ptr->next)
    {
        ptr->next->prev = ptr->prev;
    }
    free(ptr);
    totalReviews--;
}


int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    char input[16];

    // Place stdout into non-buffered mode
    setvbuf(stdout, NULL, _IONBF, 0);

    // Set the alarm
    signal(SIGALRM, alarm_handler);
    alarm(ALARM_SECONDS);

    // Send welcome message and create structures for default comments
    fputs("Welcome! Step right in and discover our hidden gem! You'll *love* the pool.\n", stdout);
    new("This charming and cozy house exudes a delightful charm that will make you feel right at home. Its warm and inviting ambiance creates a comforting haven to retreat to after a long day's hard work.");
    new("Don't let its unassuming exterior fool you; this house is a hidden gem. With its affordable price tag, it presents an excellent opportunity for first-time homebuyers or those seeking a strong investment.");
    new("Step into this well-maintained house, and you'll find a tranquil retreat awaiting you. From its tidy interior to the carefully tended garden, every corner of this home reflects the care and attention bestowed upon it.");
    new("Situated in a prime location, this house offers unparalleled convenience. Enjoy easy access to schools, shops, and public transportation, making everyday tasks a breeze.");
    new("Although not extravagant, this house offers a blank canvas for your creativity and personal touch. Imagine the endless possibilities of transforming this cozy abode into your dream home, perfectly tailored to your taste and style.");
    new("Discover the subtle surprises that this house holds. From a charming reading nook tucked away by the window to a tranquil backyard oasis, this home is full of delightful features that will bring joy to your everyday life.");
    new("Embrace a strong sense of community in this neighborhood, where friendly neighbors become extended family. Forge lasting friendships and create a sense of belonging in this warm and welcoming environment.");
    new("With its well-kept condition, this house minimizes the hassle of maintenance, allowing you to spend more time doing the things you love. Move in with peace of mind, knowing that this home has been diligently cared for.");
    new("Whether you're looking to expand your investment portfolio or start your real estate journey, this house presents a fantastic opportunity. Its affordability and potential for future value appreciation make it a smart choice for savvy buyers.");
    new("Escape the hustle and bustle of everyday life and find solace in the tranquility of this home. Its peaceful ambiance and comfortable layout provide a sanctuary where you can relax, recharge, and create beautiful memories with loved ones.");

    while (true) {
        // Require user to create a review before they can modify reviews
        if (!reviewed) {
            fputs("c|v|q> ", stdout);
        } else {
            fputs("c|v|m|d|q> ", stdout);
        }

        // Get and parse user input (bail if something went wrong)
        if (fgets(input, 16, stdin) <= 0) { goto end; }
        else {
            switch (input[0]) {
            case 'c':
                create();
                reviewed = true;
                continue;
            case 'v':
                view();
                continue;
            case 'd':
                if (reviewed) {
                    delete();
                }
                continue;
            case 'm':
                if (reviewed) {
                    modify();
                }
                continue;
            case 'q':
                if (!reviewed) {
                    fputs("Leaving so soon?\n", stdout);
                }
                goto end;
            default:
                fputs("Sorry, didn't catch that.\n", stdout);
                continue;
            }
        }
    }

end:
    fputs("Thanks for stopping by!\n", stdout);
    return 0;
}
