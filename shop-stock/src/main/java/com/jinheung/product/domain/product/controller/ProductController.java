package com.jinheung.product.domain.product.controller;

import com.google.gson.Gson;

import com.jinheung.common.dto.product.AsyncProductInfoPayload;
import com.jinheung.common.dto.product.ProductInfoDto;
import com.jinheung.common.event.MsaEvents;
import com.jinheung.product.domain.product.dto.ProductInsertRequest;

import com.jinheung.product.domain.product.jpa.service.ProductInfoService;

import io.swagger.models.auth.In;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.stream.Collectors;

@RestController
@RequiredArgsConstructor
@RequestMapping
public class ProductController {

    private final ProductInfoService productInfoService;
    private final KafkaTemplate<String, String> payloadKafkaTemplate;

    @PostMapping("/product")
    public ResponseEntity<Boolean> saveAndUpdateProduct(
//        @RequestHeader(name = AuthHeaderNames.USER_ID, required = false) Long userId,
//        @RequestHeader(name = AuthHeaderNames.USER_AUTHORITIES, required = false) List<String> authorities,
        @RequestBody ProductInsertRequest request) {

//        if(!UserRole.hasRole(authorities, UserRole.ROLE_ADMIN)) {
//            return ResponseEntity.ok(false);
//        }

        String test = "34562";
        int k  = 2;
        List<Integer> list = new ArrayList<>();
        for (int i = 0; i < test.length(); i++) {
            list.add(Integer.parseInt(String.valueOf(test.charAt(i))));
        }
        Collections.sort(list, Comparator.reverseOrder());
        String result = "";
        for (int i = 0; i < list.size() - k; i++) {
            result += list.get(i);
        }

        productInfoService.saveProductInfo(
            request.getProductId(),
            request.getName(),
            request.getDetail(),
            request.getPrice(),
            request.getStock(),
            request.getActivity()
        );
        payloadKafkaTemplate.send(MsaEvents.KAFKA_TOPIC_SEARCH_ASYNC_PRODUCT_INFO,
            new Gson().toJson( new AsyncProductInfoPayload(
                request.getProductId(),
                request.getPrice(),
                request.getStock(),
                request.getName(),
                request.getDetail(),
                request.getActivity()
            ), AsyncProductInfoPayload.class));
        return ResponseEntity.ok(true);
    }
    @GetMapping
    public ResponseEntity<List<ProductInfoDto>> findAllByIds(
        @RequestParam(name = "ids") List<Long> ids
    ) {
        return ResponseEntity.ok(productInfoService.findByIds(ids).stream()
            .map(p -> ProductInfoDto.fromEntityValues(
                p.getId(),
                p.getStockCount(),
                p.getName(),
                p.getDetail(),
                p.getPrice(),
                p.getCreatedAt(),
                p.getUpdatedAt()
            )).collect(Collectors.toList())
        );
    }
}
