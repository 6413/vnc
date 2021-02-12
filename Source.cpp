#include <WITCH/WITCH.h>
#include <WITCH/PR/PR.h>
#include <WITCH/T/T.h>
#include <WITCH/A/A.h>
#include <WITCH/RAND/RAND.h>
#include <WITCH/VAS/VAS.h>
#include <WITCH/STR/STR.h>
#include <WITCH/IO/SCR.h>
#include <WITCH/IO/print.h>
#include <WITCH/EV/EV.h>
#include <WITCH/NET/TCP/TCP.h>
#include <WITCH/NET/TCP/TLS/TLS.h>
#include <WITCH/ETC/av.h>

#include <fan/graphics.hpp>

constexpr f_t font_size = 32;

struct base_t{
	EV_t listener;
	struct{
		struct{
			VAS_t server;
			NET_TCP_t *client;
			NET_TCP_eid_t client_secret_eid;
		}tcp;
	}net;
	struct gui{

		static constexpr fan::vec2 box_size{ 200, 60 };
		static constexpr fan::vec2 border_size{ 20, 10 };
		fan::vec2 line(uint32_t n){
			return fan::vec2(50, 50.0 + (60 * n) * tr.convert_font_size(font_size));
		}
		static constexpr fan::vec2 text_box_size{ 400, 60 };
		static constexpr fan::vec2 nowhere{ -10000, -10000 };

		gui() : window(), camera(&window), boxes(&camera), tr(&camera), rtb(&camera) { }

		fan::window window;
		fan::camera camera;

		fan_2d::gui::selectable_sized_text_box boxes;
		fan_2d::gui::text_renderer tr;
		fan_2d::gui::sized_text_box rtb;

		EV_evt_t evt;
	}gui;
};

void init_tls(NET_TCP_t *tcp){
	NET_TCP_TLS_add(tcp, &TLS_generated_ctx);
}

uint32_t server_secret_connstate_cb(NET_TCP_peer_t *peer, uint64_t *secret, uint8_t *pd, uint8_t flag){
	if(!(flag & NET_TCP_connstate_succ_e))
		return 0;
	*pd = 0;
	return NET_TCP_EXT_dontgo_e;
}
uint32_t server_secret_read_cb(NET_TCP_peer_t *peer, uint64_t *secret, uint8_t *pd, uint8_t **data, uint_t *size){
	if(!*pd){
		if(*size != sizeof(*secret)){
			IO_print(FD_OUT, "[!] %08x%04x client sent wrong sized secret\n", peer->sdstaddr.ip, peer->sdstaddr.port);
			return NET_TCP_EXT_abconn_e;
		}
		if(*(uint64_t *)*data != *secret){
			IO_print(FD_OUT, "[!] %08x%04x client sent wrong secret\n", peer->sdstaddr.ip, peer->sdstaddr.port);
			return NET_TCP_EXT_abconn_e;
		}
		*pd = 1;
		peer->loff.connstate++;
		uint8_t flag = NET_TCP_EXT_signal_connstate(peer, NET_TCP_connstate_succ_e);
		if(flag & NET_TCP_EXT_abconn_e){
			NET_TCP_closehard(peer);
		}
		return NET_TCP_EXT_dontgo_e;
	}
	return 0;
}
void init_server_secret(NET_TCP_t *tcp, uint64_t secret){
	IO_print(FD_OUT, "server secret is 0x%llx\n", secret);
	uint_t EXTid = NET_TCP_EXT_new(tcp, sizeof(secret), 1);
	uint64_t *ssecret = (uint64_t *)NET_TCP_EXT_get_sockdata(tcp, EXTid);
	*ssecret = secret;
	NET_TCP_EXTcbadd(tcp, NET_TCP_oid_connstate_e, EXTid, (void *)server_secret_connstate_cb);
	NET_TCP_EXTcbadd(tcp, NET_TCP_oid_read_e, EXTid, (void *)server_secret_read_cb);
}
uint32_t client_secret_connstate_cb(NET_TCP_peer_t *peer, void *sd, uint64_t *psecret, uint8_t flag){
	if(!(flag & NET_TCP_connstate_succ_e)){
		return 0;
	}
	NET_TCP_qsend_ptr(peer, psecret, sizeof(*psecret));
	return 0;
}
NET_TCP_eid_t init_client_secret(NET_TCP_t *tcp){
	NET_TCP_eid_t eid = NET_TCP_EXT_new(tcp, 0, sizeof(uint64_t));
	NET_TCP_EXTcbadd(tcp, NET_TCP_oid_connstate_e, eid, (void *)client_secret_connstate_cb);
	return eid;
}
void init_client_secret_peerdata(NET_TCP_peer_t *peer, uint_t EXTid, uint64_t secret){
	uint64_t *psecret = (uint64_t *)NET_TCP_EXT_get_peerdata(peer, EXTid);
	*psecret = secret;
}

enum{
	PACKET_FRAME,
	PACKET_CURSOR,
	PACKET_KEY,
	PACKET_TOTAL
};

#pragma pack(push, 1)
typedef struct{
	uint16_t x;
	uint16_t y;
}packet_cursor_t;
typedef struct{
	uint16_t key;
	uint8_t action;
}packet_key_t;
#pragma pack(pop)

void send_packet_frame(NET_TCP_peer_t *peer, uint32_t size){
	#pragma pack(push, 1)
	struct{
		uint8_t type;
		uint32_t size;
	}data;
	#pragma pack(pop)
	data.type = PACKET_FRAME;
	data.size = size;
	NET_TCP_qsend_ptr(peer, &data, sizeof(data));
}

void send_packet_cursor(NET_TCP_peer_t *peer, uint16_t x, uint16_t y){
	#pragma pack(push, 1)
	struct{
		uint8_t type;
		packet_cursor_t c;
	}data;
	#pragma pack(pop)
	data.type = PACKET_CURSOR;
	data.c.x = x;
	data.c.y = y;
	NET_TCP_qsend_ptr(peer, &data, sizeof(data));
}

void send_packet_key(NET_TCP_peer_t *peer, uint16_t key, uint8_t action){
	#pragma pack(push, 1)
	struct{
		uint8_t type;
		packet_key_t k;
	}data;
	#pragma pack(pop)
	data.type = PACKET_KEY;
	data.k.key = key;
	data.k.action = action;
	NET_TCP_qsend_ptr(peer, &data, sizeof(data));
}

typedef struct{
	uint8_t type;
	union{
		struct{
			uint8_t round;
			uint32_t size;
		}frame;
	}s;
}ptype_t;

typedef bool (*packet_cb_t)(void *u0, void *u1, void *u2);
bool process_incoming_packet(void *u0, void *u1, void *u2, uint8_t *data, uint_t size, ptype_t *ptype, A_vec_t *packet, packet_cb_t frame_cb, packet_cb_t cursor_cb, packet_cb_t key_cb){
	begin_gt:
	switch(ptype->type){
		case PACKET_FRAME:{
			switch(ptype->s.frame.round){
				case 0:{
					if((packet->Current + size) >= sizeof(uint32_t)){
						uint8_t pushed = sizeof(uint32_t) - packet->Current;
						A_vec_pushbackn(packet, uint8_t, data, pushed);
						ptype->s.frame.round = 1;
						ptype->s.frame.size = *(uint32_t *)packet->ptr;
						packet->Current = 0;
						data += pushed;
						size -= pushed;
					}
					else{
						A_vec_pushbackn(packet, uint8_t, data, size);
						return 0;
					}
				}
				case 1:{
					if((packet->Current + size) >= ptype->s.frame.size){
						uint32_t pushed = ptype->s.frame.size - packet->Current;
						A_vec_pushbackn(packet, uint8_t, data, pushed);
						frame_cb(u0, u1, u2);
						data += pushed;
						size -= pushed;
						packet->Current = 0;
						ptype->type = PACKET_TOTAL;
						goto begin_gt;
					}
					else{
						A_vec_pushbackn(packet, uint8_t, data, size);
						return 0;
					}
				}
			}
			break;
		}
		case PACKET_CURSOR:{
			if((packet->Current + size) >= sizeof(packet_cursor_t)){
				uint_t pushed = sizeof(packet_cursor_t) - packet->Current;
				A_vec_pushbackn(packet, uint8_t, data, pushed);
				cursor_cb(u0, u1, u2);
				data += pushed;
				size -= pushed;
				packet->Current = 0;
				ptype->type = PACKET_TOTAL;
				goto begin_gt;
			}
			else{
				A_vec_pushbackn(packet, uint8_t, data, size);
				return 0;
			}
			break;
		}
		case PACKET_KEY:{
			if((packet->Current + size) >= sizeof(packet_key_t)){
				uint8_t pushed = sizeof(packet_key_t) - packet->Current;
				A_vec_pushbackn(packet, uint8_t, data, pushed);
				key_cb(u0, u1, u2);
				data += pushed;
				size -= pushed;
				packet->Current = 0;
				ptype->type = PACKET_TOTAL;
				goto begin_gt;
			}
			else{
				A_vec_pushbackn(packet, uint8_t, data, size);
				return 0;
			}
			break;
		}
		case PACKET_TOTAL:{
			if(!size){
				return 0;
			}
			ptype->type = data[0];
			switch(ptype->type){
				case PACKET_FRAME:{
					ptype->s.frame.round = 0;
					break;
				}
				case PACKET_CURSOR:{
					break;
				}
				case PACKET_KEY:{
					break;
				}
				default:{
					assert(0);
				}
			}
			data++;
			size--;
			goto begin_gt;
		}
	}
	return 0;
}

typedef struct{
	VAS_t peers;
	IO_SCR_t scr;
	struct{
		av_codec_t *codec;
		av_dict_t *dict;
		av_context_t *context;
		av_frame_t *frame;
		av_packet_t *packet;
		A_vec_t initialdata;
		uint64_t last;
		uint32_t fps;
	}av;
	EV_evt_t evt;
}server_sockdata_t;
typedef struct{
	VAS_node_t node;

	ptype_t ptype;
	A_vec_t packet;
}server_peerdata_t;
void server_encode_cb(EV_t *listener, EV_evt_t *evt, uint32_t flag){
	uint64_t t0 = T_nowi();
	server_sockdata_t *sd = OFFSETLESS(evt, server_sockdata_t, evt);
	uint8_t *pixelbuf = IO_SCR_read(&sd->scr);
	assert(pixelbuf);
	assert(!av_frame_write(sd->av.frame, pixelbuf, sd->scr.res.x, sd->scr.res.y, AV_PIX_FMT_BGRA));
	assert(av_inwrite(sd->av.context, sd->av.frame) > 0);
	IO_ssize_t rinread;
	while((rinread = av_inread(sd->av.context, sd->av.packet)) > 0){
		if(sd->av.packet->flags & AV_PKT_FLAG_KEY){
			sd->av.initialdata.Current = 0;
			A_vec_pushbackn(&sd->av.initialdata, uint8_t, sd->av.packet->data, rinread);
		}
		VAS_node_t inode = *VAS_road0(&sd->peers, sd->peers.src);
		while(inode != sd->peers.dst){
			NET_TCP_peer_t *peer = *(NET_TCP_peer_t **)VAS_out(&sd->peers, inode);
			send_packet_frame(peer, rinread);
			NET_TCP_qsend_ptr(peer, sd->av.packet->data, rinread);
			inode = *VAS_road0(&sd->peers, inode);
		}
	}
	assert(rinread != -1);
	sd->av.fps++;
	uint64_t t1 = T_nowi();
	uint64_t result = t1 - t0;
	uint64_t expected = (uint64_t)1000000000 / sd->av.context->time_base.den;
	if(t1 > (sd->av.last + 1000000000)){
		sd->av.last = t1;
		if(sd->av.context->time_base.den > sd->av.fps){
			IO_print(FD_OUT, "OVERLOAD fps result %lu expected %lu\n", sd->av.fps, sd->av.context->time_base.den);
		}
		sd->av.fps = 0;
	}
	if(result >= expected){
		IO_print(FD_OUT, "OVERLOAD encode result %llu expected %llu\n", result, expected);
	}
}
uint32_t server_connstate_cb(NET_TCP_peer_t *peer, server_sockdata_t *sd, server_peerdata_t *pd, uint8_t flag){
	if(flag & NET_TCP_connstate_succ_e){
		pd->ptype.type = PACKET_TOTAL;
		pd->packet = A_vec(1);
		pd->node = VAS_getnode_dst(&sd->peers);
		*(NET_TCP_peer_t **)VAS_out(&sd->peers, pd->node) = peer;
		send_packet_frame(peer, sd->av.initialdata.Current);
		NET_TCP_qsend_ptr(peer, sd->av.initialdata.ptr, sd->av.initialdata.Current);
		IO_print(FD_OUT, "[+] %08x%04x\n", peer->sdstaddr.ip, peer->sdstaddr.port);
	}
	else do{
		if(!(flag & NET_TCP_connstate_init_e)){
			break;
		}
		VAS_unlink(&sd->peers, pd->node);
		IO_print(FD_OUT, "[-] %08x%04x\n", peer->sdstaddr.ip, peer->sdstaddr.port);
	}while(0);

	return 0;
}
void server_frame_cb(NET_TCP_peer_t *peer, server_sockdata_t *sd, server_peerdata_t *pd){
	/* client can send frames to server in networkside */
}
void server_cursor_cb(NET_TCP_peer_t *peer, server_sockdata_t *sd, server_peerdata_t *pd){
	packet_cursor_t *cursor = (packet_cursor_t *)pd->packet.ptr;
	IO_print(FD_OUT, "dürürüm %lu %lu\n", cursor->x, cursor->y);
}
void server_key_cb(NET_TCP_peer_t *peer, server_sockdata_t *sd, server_peerdata_t *pd){
	packet_key_t *key = (packet_key_t *)pd->packet.ptr;
}
uint32_t server_read_cb(NET_TCP_peer_t *peer, server_sockdata_t *sd, server_peerdata_t *pd, uint8_t **data, uint_t *size){
	bool r = process_incoming_packet(peer, sd, pd, *data, *size, &pd->ptype, &pd->packet, (packet_cb_t)server_frame_cb, (packet_cb_t)server_cursor_cb, (packet_cb_t)server_key_cb);
	assert(!r);
	return 0;
}
void init_server(base_t* base){
	VAS_open(&base->net.tcp.server, sizeof(NET_TCP_t *));
}

typedef struct client_sockdata_t{
	uint8_t filler;
}client_sockdata_t;
struct client_peerdata_t{
	ptype_t ptype;
	A_vec_t packet;
	A_vec_t pixmap;

	struct{
		av_codec_t *codec;
		av_context_t *context;
		av_frame_t *frame;
		av_packet_t *packet;
	}av;

	EV_evt_t tmain;

	fan::window* window;
	fan::camera* camera;
	fan_2d::sprite* image;
};
void client_main_cb(EV_t* listener, EV_evt_t* evt, uint32_t flag){
	client_peerdata_t *pd = OFFSETLESS(evt, client_peerdata_t, tmain);

	pd->window->execute(0, [&]{
		pd->window->get_fps();
		pd->image->draw();
	});
	//fan::window::handle_events();
}
uint32_t client_connstate_cb(NET_TCP_peer_t* peer, client_sockdata_t *sd, client_peerdata_t* pd, uint8_t flag){
	if(flag & NET_TCP_connstate_succ_e){
		pd->ptype.type = PACKET_TOTAL;

		pd->packet = A_vec(1);

		pd->pixmap = A_vec(1);

		pd->av.codec = av_decoder_open(AV_CODEC_ID_H264);
		assert(pd->av.codec);		
		pd->av.context = av_context_alloc(pd->av.codec, 0);
		assert(pd->av.context);
		assert(!av_context_set(pd->av.codec, pd->av.context, 0));
		pd->av.frame = av_frame_alloc();
		assert(pd->av.frame);
		pd->av.packet = av_packet_open();
		assert(pd->av.packet);

		pd->tmain = EV_evt(.001, client_main_cb);
		EV_evtstart(peer->parent->listener, &pd->tmain);

		pd->window = new fan::window();
		pd->camera = new fan::camera(pd->window);

		pd->window->add_mouse_move_callback([pd, peer]{
			fan::vec2 position = pd->window->get_mouse_position();
			send_packet_cursor(peer, position.x, position.y);
		});

		pd->window->add_close_callback([peer]{
			NET_TCP_closehard(peer);
		});

		pd->window->add_key_callback(fan::key_escape, [&]{
			pd->window->close();
			NET_TCP_closehard(peer);
		});

		fan_2d::image_load_properties::internal_format = GL_RGB;
		fan_2d::image_load_properties::format = GL_RGB;
		fan_2d::image_load_properties::type = GL_UNSIGNED_BYTE;

		pd->image = new fan_2d::sprite(pd->camera);

		IO_print(FD_OUT, "[+] %08x%04x\n", peer->sdstaddr.ip, peer->sdstaddr.port);
	}
	else do{
		IO_print(FD_OUT, "[-] %08x%04x\n", peer->sdstaddr.ip, peer->sdstaddr.port);
		if(!(flag & NET_TCP_connstate_init_e)){
			break;
		}
		A_vec_free(&pd->packet);
		EV_evtstop(peer->parent->listener, &pd->tmain);
	}while(0);
	return 0;
}
void client_frame_cb(NET_TCP_peer_t *peer, client_sockdata_t *sd, client_peerdata_t *pd){
	IO_ssize_t routwrite = av_outwrite(pd->av.context, pd->packet.ptr, pd->packet.Current, pd->av.packet);
	assert(routwrite == pd->packet.Current);
	IO_ssize_t routread = av_outread(pd->av.context, pd->av.frame);
	assert(routread >= 0);
	if(!routread){
		return;
	}
	pd->pixmap.Current = 0;
	A_vec_handle0(&pd->pixmap, pd->av.frame->width * pd->av.frame->height * 3);
	assert(!av_frame_read(pd->av.frame, pd->pixmap.ptr, pd->av.frame->width, pd->av.frame->height, AV_PIX_FMT_RGB24));
	pd->image->reload_sprite(pd->pixmap.ptr, fan::vec2i(pd->av.frame->width, pd->av.frame->height));
	pd->image->set_size(pd->window->get_size());
}
void client_cursor_cb(NET_TCP_peer_t *peer, client_sockdata_t *sd, client_peerdata_t *pd){
	packet_cursor_t *cursor = (packet_cursor_t *)pd->packet.ptr;
}
void client_key_cb(NET_TCP_peer_t *peer, client_sockdata_t *sd, client_peerdata_t *pd){
	packet_key_t *key = (packet_key_t *)pd->packet.ptr;
}
uint32_t client_read_cb(NET_TCP_peer_t *peer, client_sockdata_t *sd, client_peerdata_t *pd, uint8_t **data, uint_t *size){
	bool r = process_incoming_packet(peer, sd, pd, *data, *size, &pd->ptype, &pd->packet, (packet_cb_t)client_frame_cb, (packet_cb_t)client_cursor_cb, (packet_cb_t)client_key_cb);
	assert(!r);
	return 0;
}
bool init_client(base_t* base){
	base->net.tcp.client = NET_TCP_alloc(&base->listener);

	init_tls(base->net.tcp.client);
	base->net.tcp.client_secret_eid = init_client_secret(base->net.tcp.client);
	uint_t EXTid = NET_TCP_EXT_new(base->net.tcp.client, sizeof(client_sockdata_t), sizeof(client_peerdata_t));
	client_sockdata_t *sd = (client_sockdata_t *)NET_TCP_EXT_get_sockdata(base->net.tcp.client, EXTid);
	NET_TCP_EXTcbadd(base->net.tcp.client, NET_TCP_oid_connstate_e, EXTid, (void *)client_connstate_cb);
	NET_TCP_EXTcbadd(base->net.tcp.client, NET_TCP_oid_read_e, EXTid, (void *)client_read_cb);

	return 0;
}

VAS_node_t command_listen(base_t *base, uint16_t port, uint64_t secret, uint32_t framerate, uint32_t rate){
	VAS_node_t node = VAS_getnode_dst(&base->net.tcp.server);
	NET_TCP_t **tcp = (NET_TCP_t **)VAS_out(&base->net.tcp.server, node);

	*tcp = NET_TCP_alloc(&base->listener);
	(*tcp)->ssrcaddr.port = port;

	/* if listen is not possible lets know it earlier to avoid big cleanup */
	/* we will call NET_TCP_listen1 in end of function */
	if(NET_TCP_listen0(*tcp)){
		NET_TCP_free(*tcp);
		VAS_unlink(&base->net.tcp.server, node);
		return (VAS_node_t)-1;
	}

	init_tls(*tcp);
	init_server_secret(*tcp, secret);
	uint_t EXTid = NET_TCP_EXT_new(*tcp, sizeof(server_sockdata_t), sizeof(server_peerdata_t));
	server_sockdata_t *sd = (server_sockdata_t *)NET_TCP_EXT_get_sockdata(*tcp, EXTid);

	VAS_open(&sd->peers, sizeof(NET_TCP_peer_t *));

	assert(!IO_SCR_open(&sd->scr));

	sd->av.codec = av_encoder_open(AV_CODEC_ID_H264);
	assert(sd->av.codec);
	sd->av.dict = 0;
	assert(av_dict_set(&sd->av.dict, "preset", "veryfast", 0) >= 0);
	assert(av_dict_set(&sd->av.dict, "tune", "zerolatency", 0) >= 0);
	sd->av.context = av_context_alloc(sd->av.codec, framerate);
	assert(sd->av.context);
	sd->av.context->width = sd->scr.res.x;
	sd->av.context->height = sd->scr.res.y;
	av_context_cbr(sd->av.context, rate);
	assert(!av_context_set(sd->av.codec, sd->av.context, &sd->av.dict));
	sd->av.frame = av_frame_open(sd->av.context);
	assert(sd->av.frame);
	sd->av.packet = av_packet_open();
	assert(sd->av.packet);
	sd->av.initialdata = A_vec(1);
	sd->av.last = T_nowi();
	sd->av.fps = 0;

	uint8_t *pixelbuf = A_resize(0, sd->scr.res.x * sd->scr.res.y * 3);
	MEM_set(0, pixelbuf, sd->scr.res.x * sd->scr.res.y * 3);
	assert(!av_frame_write(sd->av.frame, pixelbuf, sd->scr.res.x, sd->scr.res.y, AV_PIX_FMT_RGB24));
	A_free(pixelbuf);
	assert(av_inwrite(sd->av.context, sd->av.frame) > 0);
	IO_ssize_t rinread;
	while((rinread = av_inread(sd->av.context, sd->av.packet)) > 0){
		A_vec_pushbackn(&sd->av.initialdata, uint8_t, sd->av.packet->data, rinread);
	}
	assert(rinread >= 0);

	sd->evt = EV_evt((f64_t)1 / framerate, server_encode_cb);
	EV_evtstart(&base->listener, &sd->evt);

	NET_TCP_EXTcbadd(*tcp, NET_TCP_oid_connstate_e, EXTid, (void *)server_connstate_cb);
	NET_TCP_EXTcbadd(*tcp, NET_TCP_oid_read_e, EXTid, (void *)server_read_cb);

	assert(!NET_TCP_listen1(*tcp));

	return node;
}

bool command_connect(base_t *base, NET_addr_t addr, uint64_t secret){
	NET_TCP_connect0_t connect0;
	if(NET_TCP_connect0(base->net.tcp.client, addr, &connect0)){
		return 1;
	}
	init_client_secret_peerdata(connect0.peer, base->net.tcp.client_secret_eid, secret);
	if(NET_TCP_connect1(&connect0)){
		return 1;
	}
	return 0;
}

void gui_main_cb(EV_t *listener, EV_evt_t *evt, uint32_t flag){
	base_t* base = OFFSETLESS(evt, base_t, gui.evt);
	base->gui.window.execute(0, [&]{
		if (base->gui.window.key_press(fan::mouse_left)) {
			bool found = false;

			for (int i = 0; i < base->gui.rtb.size(); i++) {
				if (base->gui.rtb.inside(i)) {
					base->gui.rtb.get_mouse_cursor(i, base->gui.rtb.get_position(i), base->gui.rtb.get_size(i));
					found = true;
				}
			}

			if (!found) {
				//fan_2d::gui::current_focus[base->gui.window.get_handle()] = -1;
			}
		}

		base->gui.rtb.draw();
		base->gui.boxes.draw();
		base->gui.tr.draw();
	});

	fan::window::handle_events();
}

void run(base_t* base){
	EV_open(&base->listener);

	init_server(base);
	init_client(base);

	base->gui.window.set_vsync(true);
	base->gui.window.add_close_callback([&]{
		PR_exit(0);
	});
	base->gui.window.add_key_callback(fan::key_escape, [&]{
		PR_exit(0);
	});

	base->gui.boxes.push_back(L"connect", font_size, base->gui.window.get_size() / 2 - fan::vec2(base->gui.box_size.x / 2, base->gui.box_size.y - 100), base->gui.box_size, base->gui.border_size, fan::colors::purple - 0.4);
	base->gui.boxes.push_back(L"listen", font_size, base->gui.boxes.get_position(0) + fan::vec2(0, base->gui.boxes.get_size(0).y + 1), base->gui.box_size, base->gui.border_size , fan::colors::purple - 0.4);
	base->gui.boxes.push_back(L"start", font_size, base->gui.boxes.get_position(1) + fan::vec2(0, base->gui.boxes.get_size(1).y + 1),  base->gui.box_size, base->gui.border_size, fan::colors::purple - 0.4);

	base->gui.tr.push_back(L"Ip: ", base->gui.nowhere, fan::colors::white, font_size);
	base->gui.tr.push_back(L"Port: ", base->gui.nowhere, fan::colors::white, font_size);
	base->gui.tr.push_back(L"Secret: ", base->gui.nowhere, fan::colors::white, font_size);
	base->gui.tr.push_back(L"FPS: ", base->gui.nowhere, fan::colors::white, font_size);
	base->gui.tr.push_back(L"Rate: ", base->gui.nowhere, fan::colors::white, font_size);

	base->gui.rtb.push_back(L"", font_size, base->gui.nowhere, base->gui.text_box_size, base->gui.border_size, fan::colors::cyan - 0.9);
	base->gui.rtb.push_back(L"", font_size, base->gui.nowhere, base->gui.text_box_size, base->gui.border_size, fan::colors::cyan - 0.9);
	base->gui.rtb.push_back(L"", font_size, base->gui.nowhere, base->gui.text_box_size, base->gui.border_size, fan::colors::cyan - 0.9);
	base->gui.rtb.push_back(L"", font_size, base->gui.nowhere, base->gui.text_box_size, base->gui.border_size, fan::colors::cyan - 0.9);

	base->gui.window.add_resize_callback([&] {
		for (int i = 0; i < base->gui.tr.size(); i++) {
			const auto offset = fan_2d::gui::get_resize_movement_offset(base->gui.camera.m_window);
			base->gui.tr.set_position(i, base->gui.tr.get_position(i) + offset);
		}
	});

	base->gui.rtb.set_input_callback(0);
	base->gui.rtb.set_input_callback(1);
	base->gui.rtb.set_input_callback(2);
	base->gui.rtb.set_input_callback(3);

	base->gui.boxes.on_click([&] (uint_t i) {
		auto selected = base->gui.boxes.get_selected();

		if (selected != fan::uninitialized) {
			base->gui.boxes.set_box_color(selected, fan::colors::purple - 0.4);
		}

		switch (i) {
			case 0:
			{

				base->gui.rtb.set_text(0, L"127.0.0.1");
				base->gui.rtb.set_text(1, L"8081");
				base->gui.rtb.set_text(2, L"123");
				base->gui.rtb.set_text(3, L"200000");

				f_t longest = base->gui.tr.get_longest_text();

				f_t y = 0;

				for (int i = 0; i < 3; i++) {
					base->gui.rtb.set_position(i, base->gui.line(0) + fan::vec2(longest, y));
					base->gui.tr.set_position(i, base->gui.rtb.get_position(i) - fan::vec2(longest, -(base->gui.rtb.get_size(i).y * 0.5 - base->gui.tr.get_text_size(base->gui.tr.get_text(i), font_size).y * 0.5)));
					y += base->gui.rtb.get_size(i).y + 1;
				}

				base->gui.rtb.set_position(3, base->gui.nowhere);

				base->gui.tr.set_position(3, base->gui.nowhere);
				base->gui.tr.set_position(4, base->gui.nowhere);

				base->gui.boxes.set_box_color(i, fan::colors::purple - 0.3);
				base->gui.boxes.set_selected(i);

				fan_2d::gui::current_focus[base->gui.window.get_handle()] = base->gui.rtb.get_focus_id(0);
				base->gui.rtb.set_cursor_visible(0);
				base->gui.rtb.set_focus_end(3);
				break;
			}
			case 1:
			{
				base->gui.rtb.set_text(0, L"8081");
				base->gui.rtb.set_text(1, L"123");
				base->gui.rtb.set_text(2, L"10");


				f_t longest = base->gui.tr.get_longest_text();

				f_t y = 0;

				base->gui.tr.set_position(0, base->gui.nowhere);

				for (int i = 0; i < 4; i++) {
					base->gui.rtb.set_position(i, base->gui.line(0) + fan::vec2(longest, y));
					base->gui.tr.set_position(i + 1, base->gui.rtb.get_position(i) - fan::vec2(longest, -(base->gui.rtb.get_size(i).y * 0.5 - base->gui.tr.get_text_size(base->gui.tr.get_text(i + 1), font_size).y * 0.5)));
					y += base->gui.rtb.get_size(i).y + 1;
				}

				base->gui.boxes.set_box_color(i, fan::colors::purple - 0.3);
				base->gui.boxes.set_selected(i);

				fan_2d::gui::current_focus[base->gui.window.get_handle()] = base->gui.rtb.get_focus_id(0);
				base->gui.rtb.set_cursor_visible(0);
				base->gui.rtb.set_focus_end(4);

				break;
			}
			case 2:
			{
				auto selected = base->gui.boxes.get_selected();
				switch(selected){
					case 0:{
						uint8_t sip[4];
						uint_t pi = 0;

						auto wstr = base->gui.rtb.get_line(0, 0);

						if (STR_rscancc(std::string(wstr.begin(), wstr.end()).c_str(), &pi, "(ov8u).(ov8u).(ov8u).(ov8u)", &sip[3], &sip[2], &sip[1], &sip[0])){
							throw std::runtime_error("failed to parse ip");
						}

						uint64_t secret = std::stoi(base->gui.rtb.get_line(2, 0));

						NET_addr_t net_addr;
						net_addr.port = std::stoi(base->gui.rtb.get_line(1, 0));
						net_addr.ip = *(uint32_t*)sip;

						bool r = command_connect(base, net_addr, secret);
						assert(!r);

						break;
					}
					case 1:{
						uint16_t port = std::stoi(base->gui.rtb.get_line(0, 0));
						uint64_t secret = std::stoi(base->gui.rtb.get_line(1, 0));
						uint32_t fps = std::stoi(base->gui.rtb.get_line(2, 0));
						uint32_t rate = std::stoi(base->gui.rtb.get_line(3, 0));

						VAS_node_t node = command_listen(base, port, secret, fps, rate);
						assert(node != (VAS_node_t)-1);

						break;
					}
				}
				break;
			}
		}
	});

	base->gui.evt = EV_evt(.001, gui_main_cb);
	EV_evtstart(&base->listener, &base->gui.evt);

	EV_start(&base->listener);
}

int main(){
	base_t base;
	run(&base);
	return 0;
}
