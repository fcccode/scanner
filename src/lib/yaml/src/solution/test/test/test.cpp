// test.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"


int read_handler(void * ext, unsigned char * buffer, size_t size, size_t * length)
{
    int error = 1;

    *buffer = 0;
    *length = 0;

    return error ? 0 : 1;
}


bool test()
/*

https://pyyaml.org/wiki/LibYAML
*/
{
    yaml_parser_t parser;
    yaml_event_t event;
    bool ret = true;

    int done = 0;
    
    yaml_parser_initialize(&parser);/* Create the Parser object. */

    //void * ext = NULL;/* Set a generic reader. */
    //yaml_parser_set_input(&parser, read_handler, ext);
    //yaml_parser_set_input_file(&parser, stdin);

    /* Set a string input. */
    const char * input = u8R"("%YAML 1.1
        -- -
        [1, 2, 3]")";
    size_t length = strlen(input);

    yaml_parser_set_input_string(&parser, (const unsigned char *)input, length);
    yaml_parser_update_buffer(&parser, length);
    
    //FILE * input = fopen("...", "rb");/* Set a file input. */
    //yaml_parser_set_input_file(&parser, input);       

    yaml_emitter_t emitter;
#define BUFFER_SIZE 65536
    unsigned char buffer[BUFFER_SIZE + 1];
    size_t written = 0;
    memset(buffer, 0, BUFFER_SIZE + 1);

    assert(yaml_emitter_initialize(&emitter));
    //if (canonical) {
    //    yaml_emitter_set_canonical(&emitter, 1);
    //}
    //if (unicode) {
    //    yaml_emitter_set_unicode(&emitter, 1);
    //}
    yaml_emitter_set_output_string(&emitter, buffer, BUFFER_SIZE, &written);
    yaml_emitter_open(&emitter);    

    /* Read the event sequence. */
    while (!done) {        
        if (!yaml_parser_parse(&parser, &event)) {/* Get the next event. */
            ret = false;
            break;
        }

        /*
          Process the event.
        */
        {
            yaml_document_t document;
            assert(yaml_parser_load(&parser, &document));
            int d = (!yaml_document_get_root_node(&document));
            assert(yaml_emitter_dump(&emitter, &document));
            assert(yaml_emitter_flush(&emitter));

            yaml_document_delete(&document);
        }
        
        done = (event.type == YAML_STREAM_END_EVENT);/* Are we finished? */
        
        yaml_event_delete(&event);/* The application is responsible for destroying the event object. */
    }
    
    yaml_parser_delete(&parser);/* Destroy the Parser object. */
    yaml_emitter_close(&emitter);
    yaml_emitter_delete(&emitter);
    return ret;
}


int main(int argc, char * argv[])
{
    //get_version();
    scanner(argc, argv);
    //parser(argc, argv);
    //dumper(argc, argv);

    //test();



}
