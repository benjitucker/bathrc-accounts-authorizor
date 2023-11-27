FROM public.ecr.aws/lambda/provided:al2 as builder

# TODO when github supports ARM based hosted runners, swithc to ar as its cheaper to run
# https://github.blog/changelog/2023-10-30-accelerate-your-ci-cd-with-arm-based-hosted-runners-in-github-actions/

# install compiler
RUN yum install -y golang wget tar
RUN go env -w GOPROXY=https://proxy.golang.org

# Set necessary environmet variables needed for our image
ENV GOOS=linux \
    GOARCH=amd64

# cache dependencies
ADD go.mod go.sum ./
RUN go mod download

# Add the code to the container
ADD . .

# build
RUN go build -o /main

# copy artifacts to a clean image
FROM public.ecr.aws/lambda/provided:al2
COPY --from=builder /main /main

ENTRYPOINT [ "/main" ]
