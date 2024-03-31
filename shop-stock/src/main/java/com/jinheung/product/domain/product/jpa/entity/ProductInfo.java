package com.jinheung.product.domain.product.jpa.entity;

import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import javax.persistence.*;
import java.time.LocalDateTime;

@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Builder
@Getter
@Table(name = "product_infos")
@Entity
@Setter
public class ProductInfo {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "product_info_id")
    private Long id = null;
    @Column(name = "stock_count")
    private Integer stockCount;
    @Column
    private String name;
    @Column
    private String detail;
    @Column
    private Integer price;
    @Column
    private Boolean activity;
    @Column(name = "created_at")
    @CreationTimestamp
    private LocalDateTime createdAt;
    @Column(name = "updated_at")
    @UpdateTimestamp
    private LocalDateTime updatedAt;

    public boolean reduceStock(int count) {
        stockCount -= count;
        if(stockCount < 0) {
            stockCount += count;
            return false;
        } else return true;
    }
}
