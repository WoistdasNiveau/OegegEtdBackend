package at.oegeg.etd.authcomponent.config;

import org.springframework.stereotype.Component;

@Component
public class AuthorizationWebInterceptor //implements WebGraphQlInterceptor Delete if no problems occur
{

    //@Override
    //public Mono<WebGraphQlResponse> intercept(WebGraphQlRequest request, Chain chain)
    //{
    //    String authorization = request.getHeaders().getFirst(AUTHORIZATIONHEADER);
    //    request.configureExecutionInput((input, inputBuilder )->
    //            inputBuilder
    //                    .graphQLContext(contextBuilder -> contextBuilder.put(AUTHORIZATIONHEADER,authorization))
    //                    .build());
    //    return chain.next(request);
    //}
//
    //@Override
    //public WebGraphQlInterceptor andThen(WebGraphQlInterceptor nextInterceptor)
    //{
    //    return WebGraphQlInterceptor.super.andThen(nextInterceptor);
    //}
//
    //@Override
    //public Chain apply(Chain chain)
    //{
    //    return WebGraphQlInterceptor.super.apply(chain);
    //}
}
