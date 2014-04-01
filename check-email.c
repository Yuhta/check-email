#define _GNU_SOURCE

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>
#include <error.h>
#include <iconv.h>
#include <libnetrc.h>
#include <obstack.h>

static FILE * dev_null;

void *
xmalloc (size_t size)
{
  register void * value = malloc (size);
  if (!value) error (EXIT_FAILURE, 0, "virtual memory exhausted");
  return value;
}

static CURLcode
x_curl_easy_perform (CURL * curl)
{
  CURLcode res = curl_easy_perform (curl);
  if (res != CURLE_OK) error (0, 0, curl_easy_strerror (res));
  return res;
}

static char *
comma_separated_uids (char * s)
{
  char * head     = "* SEARCH ";
  size_t head_len = strlen (head);
  char * uids     = s + head_len;
  assert (memcmp (s, head, head_len - 1) == 0);
  for (char * c = uids; *c; c++)
    switch (*c)
      {
      case  ' ': *c = ','; break;
      case '\r':
      case '\n': *c = 0;
      }
  return uids;
}

#define obstack_chunk_alloc xmalloc
#define obstack_chunk_free  free

static void *
obstack_finish0 (struct obstack * obstack_ptr)
{
  obstack_1grow (obstack_ptr, 0);
  return obstack_finish (obstack_ptr);
}

static void
find_encoded_word (const char * s,
                   const char ** start, const char ** end)
{
  const char * p, * q = s;
  while ((p = strstr (q, "=?")))
    {
      q = p + 2;
      while (isgraph (*q) && !strchr ("()<>@,;:\"/[]?.=", *q)) q++;
      if (q[0] == '?' && strchr ("BbQq", q[1]) && q[2] == '?')
        {
          q += 3;
          while (isprint (*q) && !(q[0] == '?' && q[1] == '=')) q++;
          if (q[0] == '?' && q[1] == '=')
            {
              *start = p;
              *end   = q + 2;
              return;
            }
          else q++;
        }
    }
  *start = *end = NULL;
}

static const char *
squeeze_ws_after (struct obstack * obstack_ptr, const char * s)
{
  if (strchr (" \t\r\n", *s))
    {
      while (strchr (" \t\r\n", *s)) s++;
      if (*s) obstack_1grow (obstack_ptr, ' ');
    }
  return s;
}

static const char *
ws_ptr_before (const char * s, const char * limit)
{
  do {s--;} while (s >= limit && strchr (" \t\r\n", *s));
  return s + 1;
}

static const char INDEX_BASE64[128] =
  {-1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
   -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
   -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,62, -1,-1,-1,63,
   52,53,54,55, 56,57,58,59, 60,61,-1,-1, -1, 0,-1,-1,
   -1, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,
   15,16,17,18, 19,20,21,22, 23,24,25,-1, -1,-1,-1,-1,
   -1,26,27,28, 29,30,31,32, 33,34,35,36, 37,38,39,40,
   41,42,43,44, 45,46,47,48, 49,50,51,-1, -1,-1,-1,-1};

static const char INDEX_HEX[128] =
  {-1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
   -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
   -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    0, 1, 2, 3,  4, 5, 6, 7,  8, 9,-1,-1, -1,-1,-1,-1,
   -1,10,11,12, 13,14,15,-1, -1,-1,-1,-1, -1,-1,-1,-1,
   -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
   -1,10,11,12, 13,14,15,-1, -1,-1,-1,-1, -1,-1,-1,-1,
   -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1};

static void
decode (char encoding, char * s)
{
  switch (encoding)
    {
    case 'B':
      assert (strlen (s) % 4 == 0);
      char g[3];
      for (char * p = s; *p; p += 4)
        {
          g[0] = ((INDEX_BASE64[(int)p[0]] << 2) |
                  (INDEX_BASE64[(int)p[1]] >> 4));
          g[1] = ((INDEX_BASE64[(int)p[1]] << 4) |
                  (INDEX_BASE64[(int)p[2]] >> 2));
          g[2] = ((INDEX_BASE64[(int)p[2]] << 6) |
                  (INDEX_BASE64[(int)p[3]]));
          memcpy (s, g, 3);
          s += 3;
        }
      *s = 0;
      break;
    case 'Q':
      for (char * p = s; *p; p++)
        {
          if (*p == '_') *s++ = ' ';
          else if (p[0] == '=' &&
                   INDEX_HEX[(int)p[1]] != -1 &&
                   INDEX_HEX[(int)p[2]] != -1)
	    {
              *s++ = (INDEX_HEX[(int)p[1]] << 4) | INDEX_HEX[(int)p[2]];
	      p += 2;
	    }
          else *s++ = *p;
        }
      *s = 0;
      break;
    default:
      error (0, 0, "Unknown encoding: %c", encoding);
    }
}

static void
rfc2047_decode_word (struct obstack * obstack_ptr, const char * s)
{
  assert (s[0] == '=' && s[1] == '?');
  const char * charset_beg = s + 2;
  const char * charset_end = strchr (charset_beg, '?');
  char * charset = strndupa (charset_beg, charset_end - charset_beg);

  char encoding = toupper (charset_end[1]);
  assert (charset_end[2] == '?');

  const char * text_beg = charset_end + 3;
  const char * text_end = strstr (text_beg, "?=");
  size_t text_len = text_end - text_beg;
  char * text = strndupa (text_beg, text_len);
  decode (encoding, text);

  size_t out_avail = text_len * 4 + 1;
  char * text_ptr = text, out[out_avail], * out_ptr = out;
  iconv_t cd = iconv_open ("UTF-8", charset);
  if (cd == (iconv_t)-1) perror ("iconv_open");
  if (iconv (cd,
             &text_ptr, &text_len, &out_ptr, &out_avail) == (size_t)-1)
    perror ("iconv");
  assert (out_avail >= 1);
  *out_ptr = 0;
  obstack_grow (obstack_ptr, out, strlen (out));
  if (iconv_close (cd) != 0) perror ("iconv_close");
}

static char *
rfc2047_decode (struct obstack * obstack_ptr, const char * s)
{
  const char * p, * q;
  int found_encoded = 0;
  while (*s)
    {
      find_encoded_word (s, &p, &q);
      if (!p)
        {
          if (found_encoded) s = squeeze_ws_after (obstack_ptr, s);
          obstack_grow (obstack_ptr, s, strlen (s));
          break;
        }
      if (found_encoded)
        {
          while (strchr (" \t\r\n", *s)) s++;
          if (s != p) obstack_1grow (obstack_ptr, ' ');
        }
      if (p != s)
        {
          const char * ws = ws_ptr_before (p, s);
          obstack_grow (obstack_ptr, s, ws - s);
          if (ws != p) obstack_1grow (obstack_ptr, ' ');
        }
      rfc2047_decode_word (obstack_ptr, p);
      found_encoded = 1;
      s = q;
    }
  return obstack_finish0 (obstack_ptr);
}

static void
parse_fetch_result_item (char * item)
{
  char * tok_save_ptr, * tok = strtok_r (item, "\r\n", &tok_save_ptr);
  char * from, * subject;
  char ** curr_ptr = NULL;
  struct obstack obstack_headers;
  obstack_init (&obstack_headers);

  while (tok)
    {
      if (strncmp (tok, "From: ", strlen ("From: ")) == 0)
        {
          if (curr_ptr) *curr_ptr = obstack_finish0 (&obstack_headers);
          obstack_grow (&obstack_headers, tok, strlen (tok));
          curr_ptr = &from;
        }
      else if (strncmp (tok, "Subject: ", strlen ("Subject: ")) == 0)
        {
          if (curr_ptr) *curr_ptr = obstack_finish0 (&obstack_headers);
          obstack_grow (&obstack_headers, tok, strlen (tok));
          curr_ptr = &subject;
        }
      else if (curr_ptr)
        obstack_grow (&obstack_headers, tok, strlen (tok));
      else error (0, 0, "Malformed fetch result: %s", tok);
      tok = strtok_r (NULL, "\r\n", &tok_save_ptr);
    }
  if (curr_ptr) *curr_ptr = obstack_finish0 (&obstack_headers);

  from    = rfc2047_decode (&obstack_headers, from);
  subject = rfc2047_decode (&obstack_headers, subject);

  printf ("%s\n%s\n", from, subject);
  obstack_free (&obstack_headers, NULL);
}

static void
parse_fetch_results (char * results)
{
  FILE * in       = fmemopen (results, strlen (results), "r");
  char * line     = NULL;
  size_t line_len = 0;
  int    first    = 1;

  while (getline (&line, &line_len, in) >= 0)
    {
      char * s = strrchr (line, '{');
      int buf_len, anum;
      if (s)
        {
          sscanf (s, "{%d}", &buf_len);
          buf_len += 3;          // Extended to include ")\r\n"
          char * buf = xmalloc (buf_len);
          fread (buf, sizeof (char), buf_len, in);
          buf[buf_len - 5] = 0;  // Strip trailing "\r\n)\r\n"

          if (first) first = 0;
          else putc ('\n', stdout);
          parse_fetch_result_item (buf);

          free (buf);
        }
      else if (sscanf (line, "A%d OK Success", &anum) != 1)
        error (0, 0, "Error parse line: %s", line);
    }

  if (line) free (line);
  fclose (in);
}

static void
print_new_mail_summaries (const struct netrc_entry * netrc,
                          const char * url)
{
  char * buf;
  size_t buf_len;
  FILE * stream = open_memstream (&buf, &buf_len);
  CURL * curl   = curl_easy_init ();

  curl_easy_setopt (curl, CURLOPT_URL,           url);
  curl_easy_setopt (curl, CURLOPT_USERNAME,      netrc->login);
  curl_easy_setopt (curl, CURLOPT_PASSWORD,      netrc->password);
  curl_easy_setopt (curl, CURLOPT_USE_SSL,       CURLUSESSL_TRY);
  curl_easy_setopt (curl, CURLOPT_WRITEDATA,     dev_null);
  if (netrc->port) curl_easy_setopt (curl, CURLOPT_PORT, netrc->port);
  curl_easy_setopt (curl, CURLOPT_CUSTOMREQUEST, "EXAMINE INBOX");
  x_curl_easy_perform (curl);

  curl_easy_setopt (curl, CURLOPT_CUSTOMREQUEST, "SEARCH UNSEEN");
  curl_easy_setopt (curl, CURLOPT_WRITEDATA,     stream);
  x_curl_easy_perform (curl);
  fflush (stream);

  char * uids = comma_separated_uids (buf);
  if (strlen (uids) > 0)
    {
      char * cmd;
      if (asprintf (&cmd,
                    "FETCH %s BODY[HEADER.FIELDS (FROM SUBJECT)]",
                    uids) < 0)
        error (EXIT_FAILURE, 0, "virtual memory exhausted");
      rewind (stream);
      curl_easy_setopt (curl, CURLOPT_CUSTOMREQUEST, cmd);
      curl_easy_setopt (curl, CURLOPT_HEADER,        1);
      curl_easy_setopt (curl, CURLOPT_WRITEDATA,     dev_null);
      curl_easy_setopt (curl, CURLOPT_WRITEHEADER,   stream);
      x_curl_easy_perform (curl);
      free (cmd);
      fflush (stream);
      parse_fetch_results (buf);
    }

  curl_easy_cleanup (curl);
  fclose (stream);
  free (buf);
}

int
main (int argc, char ** argv)
{
  dev_null = fopen ("/dev/null", "w");

  if (argc < 2)
    {
      fprintf (stderr, "Usage: %s HOST [USERNAME]\n", argv[0]);
      exit (EXIT_FAILURE);
    }
  struct netrc_entry netrc;
  memset (&netrc, 0, sizeof (netrc));
  netrc.machine = argv[1];
  if (argc > 2) netrc.login = argv[2];
  if (search_in_netrc (&netrc, NULL) != NETRC_SUCCESS)
    error (0, 0, "netrc lookup error");

  char * url;
  if (asprintf (&url, "imaps://%s", netrc.machine) < 0)
    error (EXIT_FAILURE, 0, "virtual memory exhausted");
  print_new_mail_summaries (&netrc, url);
  free (url);

  if (netrc.login && argc <= 2) free (netrc.login);
  if (netrc.password)           free (netrc.password);
  fclose (dev_null);
  return 0;
}
